# BFT Comparison — Stellereum vs. Tendermint/Cosmos, HotStuff/Aptos, Narwhal/Bullshark→Mysticeti/Sui, Tower BFT→Votor/Solana, Gasper/Ethereum

Status: research + design doc. No live ops, no builds/tests, no code changes.
Ground truth for OUR design: `stellereum/src/consensus.rs`, `stellereum/src/staking.rs`,
`stellereum/src/light_client.rs`, `stellereum/src/runtime.rs`, `stellereum/src/main.rs`,
`docs/specs/01_ARCHITECTURE_OVERVIEW.md`, `docs/specs/02_CRYPTO_AND_PQ.md`,
`docs/specs/04_NETWORK_AND_CONSENSUS.md`, `docs/PROPOSER_REWORK.md`.
External facts: web search, Oct–Nov 2026. Numbers are "as reported"; live parameters drift by governance.

> **Stellereum numbers in this comparison are ruleset-v1 era.** Current ruleset
> v5: base round timeout `3 000 ms` (no `STELL_ROUND_TIMEOUT_MS` env), µQC cap
> 128 seats, downtime threshold 42 misses / 500-height cooldown, MMR/MEV epoch
> 500, and **no** `STELL_VRF_ACTIVATION_HEIGHT` gate (parent-hash sortition is
> canonical). Use `docs/RULESET_V5.md` for current values.

## 0. One-paragraph summary

Stellereum today is a **Tendermint-style two-phase (prevote/precommit) BFT** with per-(height, round)
quorums at `floor(2W/3)+1` voting power, hash-slot weighted proposer selection, Tendermint-style
value locking, same-round prevote+precommit agreement before decision, and a large stack of
liveness hardening (deterministic backoff, adaptive slow-proposer extension, nil-breaker, deadlock
breaker, polka ledger, re-phase window) that exists because the live network has repeatedly parked
on stalls. Finality is **single-height, same-round, precommit-QC-gated** (no pipelined 2-chain/3-chain
commit rule), measured live at **~2–3 s/block with ~0.5 s bursts** (spec 04). Each mature chain below
differs on at least one load-bearing axis: Cosmos has 21-day unbonding + mature evidence gossip +
IBC light clients; Aptos pipelines QCs (Jolteon 2-chain) and leans on reputation-weighted leaders
with **no slashing at all**; Sui removed the leader bottleneck entirely (DAG, every validator
proposes; ~400 ms commits); Solana replaced voting-with-transactions first by vote-towers and now
by off-chain BLS certificates (Votor, ~150 ms target, 80%/60% stake thresholds); Ethereum splits
finality into two layers (fast LMD-GHOST head vs. ~13–19 min Casper-FFG checkpoint finality) with
the richest slashing/fork-choice/light-client machinery and the heaviest validator UX cost (32 ETH,
queues, weak subjectivity).

## 1. Same-shape comparison table

| Axis | Tendermint / Cosmos (CometBFT) | HotStuff / Aptos (AptosBFT v4, Jolteon) | Narwhal/Bullshark → Mysticeti / Sui | Tower BFT → Votor / Solana | Gasper / Ethereum | **Stellereum (OURS, as implemented)** |
|---|---|---|---|---|---|---|
| Round structure | `NewHeight → (Propose → Prevote → Precommit)+ → Commit`; 3 steps/round, multi-round per height; PoLC (`validValue`/`validRound`) lets locked validators unlock on newer polka. | Rounds ("views"); leader proposes block extending highest QC; validators vote; QC forms; **pipelined 2-chain commit** (Jolteon): block B commits when child B′ and grandchild B″ certify it. Order-Votes (AIP-89, Jolteon*) cuts common case 5→3 message delays via all-to-all votes. | **No single-proposer rounds.** DAG: every validator proposes each round; vertices = proposals, edges = votes. Bullshark: commit every ~2 rounds via anchor sub-DAG + zero-overhead local ordering. Mysticeti (current): uncertified DAG, 3-message-delay commits (theoretical min), multiple anchors/round, implicit votes via DAG links. | Tower: slots (~400 ms, now stepping to 200 ms) paced by PoH; per-slot leader; votes are transactions stacking lockouts. Votor (live 2026-10-21, epoch 1064, slot 459,653,000): 1–2 voting rounds per slot, BLS certificates carried in block footer, PoH no longer paces blocks. | Slots (12 s) grouped in epochs (32 slots, 6.4 min). Per slot: 1 proposer + attestation committee. Per epoch: justify/finalize checkpoints (Casper-FFG) on top of LMD-GHOST fork choice head. Two finalities: available head (fast) vs. finalized checkpoint (slow). | **Tendermint-shaped**: `Propose → Prevote → Precommit → Commit`, multi-round per height (`stellereum/src/consensus.rs:1-16`). Steps `Propose/Prevote/Precommit/Commit` in `HeightConsensus`; pipeline is across heights (`ConsensusDriver`), not a chained commit rule: decision needs a **same-round** prevote QC **and** precommit QC for the same block (`consensus.rs:4436-4466`). |
| QC formation rule | +2/3 prevotes = polka → precommit; +2/3 precommits = commit. Votes for H+1 carried as `LastCommit` in next block. | 2f+1 votes = QC; QC linked into next proposal; 2-chain (Jolteon) or 3-chain (HotStuff) of QCs commits. Quorum Store (Narwhal-inspired mempool) separates dissemination from ordering. | Certificates = 2/3 stake references in DAG; Mysticeti-C: commit on 3 rounds of DAG messages; fast path for owned objects skips consensus (Byzantine consistent broadcast only). | Tower: 2/3 supermajority votes per slot; 32 stacked votes = "rooted". Votor: fast-finalize = ≥80% notarize in round 1; else notarize (60–80%) + finalize (≥60% round 2); skip cert ≥60%. BLS-aggregated, ~1 KB/slot (was ~500 KB/slot vote txs). | Attestations aggregated per committee; supermajority link between checkpoints justifies; second link finalizes. Sync committee (512, ~27.3 h periods) signs headers for light clients. | **Strict `floor(2W/3)+1` power** (`consensus.rs:1389-1405`, `consensus_quorum_min`); empty set returns `u64::MAX` so it can never finalize. `qc_meets_quorum` = signed power ≥ quorum under the set **in force at that height** (`consensus.rs:1431-1444`). µQC accelerator only: `max(2/3 committee, strict majority of network)` (`consensus.rs:844-883`); full Ed25519 QC stays authoritative. QC verify: Ed25519 batch → per-sig fallback, plus BLS-aggregate and PQ µQC/CEC envelope paths; signer cap 4096 as DoS bound (`consensus.rs:2806-2916`, `MAX_COMMIT_CERT_SIGNERS`, `consensus.rs:192`). |
| Proposer / leader selection | Deterministic weighted round-robin by voting power (+ proposer priority); known schedule, stake-weighted. | Per-round leader; round-robin **and** reputation-based (miss-prone leaders demoted); stake-weighted votes; leader reputation is the main stall defense (Shoal++ analysis: Jolteon latency largely unaffected by faults thanks to it). | **All validators propose every round** (no leader); Bullshark/Mysticeti elect anchors after the fact (reputation-aware in Shoal/Hammerhead variants; base Mysticeti waits rather than re-electing). Censorship resistance via parallel proposing. | Leader schedule per epoch (432k slots), stake-weighted random, known ahead. Votor keeps slot leaders; Rotor (propagation redesign) unscheduled. | RANDAO + effective balance (cap 32 ETH counts) picks 1 proposer/slot + committees; lookahead ~1 epoch; proposer boosting defends reorg/balancing attacks. | **Hash-slot, stake-weighted, deterministic**: `slot = BLAKE3("STELL_PROPOSER_V1"‖height‖round) mod (total/gcd)` over explicit-sorted cumulative power table (`consensus.rs:1454-1524`). GCD normalization + hash slot fixed two observed liveness bugs (lexicographically-first monopoly; down-node monopoly at live powers). Lookahead inherent, accepted for testnet. VRF/beacon draw is NOT gated by an env switch: the compiled `BEACON_DRAW_ACTIVATION_HEIGHT`/`CNVRF_V3_ACTIVATION_HEIGHT` gates are `u64::MAX`, so parent-hash is canonical. |
| Finality latency (numbers) | Cosmos Hub: block ~5.7–6 s (2026-10-15: 9,500 blocks ≈ 15 h ⇒ ~5.7 s); **instant single-block finality** once committed. | ~0.9 s pipelined finality commonly cited; sub-second common case; Order-Votes trims 5→3 delays. Common case ≈ 2 network round trips (<300 ms RTT worldwide) + execution. | Bullshark era: p50 ~1.9 s → Mysticeti-C: p50 ~400 ms prod, p50/p95 650/975 ms at 137 validators; owned-object fast path ~250 ms; lab 300–400k TPS < 1 s. | Tower: confirmed ~0.4–1 s, **rooted/finalized ~12.8 s** (32 slots × 400 ms). Votor target **~150 ms** (fast path ~100 ms @≥80%, slow ~150 ms @60%+60%); 96% fast-path on test cluster; "expectation, not constant". | Head available in 1 slot (12 s); **finalized typically 2 epochs ≈ 12.8–19 min** (justify + finalize); inactivity leak after 4 non-finalizing epochs. Weak-subjectivity checkpoint needed to sync. | **Measured live 2026-10-28: sustained ~2–3 s/block, p50 bursts ~0.5 s; residual to 0.5 s sustained = WAN RTT floor + 1-vCPU members** (spec 04). Tick floor 50 ms (ruleset v5), base timeout 3000 ms (compiled `FROZEN_ROUND_TIMEOUT_BASE_MS`; the old `STELL_ROUND_TIMEOUT_MS` env is gone), deterministic backoff +500 ms/round cap +10 s, adaptive slow-proposer +500 ms/miss cap +5 s. Nil prevote at ~2× timeout; DOWN-PROPOSER fast timeout 800 ms. Straggler-grace extension (PROPOSER_REWORK, sim-only): 0→1,787 finals/20 virtual-min, waste 1.0→~0.06. |
| Slashing / evidence | On-chain evidence: `DuplicateVote` + `LightClientAttack`; app (Cosmos SDK `x/slashing`, `x/evidence`) slashes: downtime 0.01% + 10-min jail (+unbonding), double-sign 5% + tombstone (permanent). Evidence TTL ~21 d (unbonding window). | **No slashing implemented** (docs + StakingRewards 2026): penalty = missed rewards (proposer-performance-scaled) + pool <1M APT inactive. Future slashing discussed, not scheduled. | No principal burn for downtime: **tallying rule** slashes *that epoch's rewards* (peers score 0; 2/3-zero ⇒ reward slash); stake-threshold ejection only (7-epoch grace <2 voting-power units, removal <1; ~24 h epochs). Principal at risk only via explicit equivocation paths, not liveness. | Tower era: **no programmatic slashing** (social/halting only); lockout violation detectable (Votalizer bot) but unenforced by runtime. SIMDs 180/204/212 lay groundwork; Alpenglow voting violations (conflicting Notarize/Skip) planned post-launch. Costs today = missed vote credits/inflation/APY. | Richest: double-propose, double-vote (same target), surround-vote ⇒ burn (initial ~0.0078 ETH @32 ETH) + 36-d exit + day-18 correlation penalty up to **100%**; proposer gets slashing reward. Plus penalties (missed duties) and **inactivity leak** (bleeds offline stake until 2/3 restored). | **Evidence as deterministic inputs**: vote-equivocation (`EquivocationEvidence`, `consensus.rs:1924-2087`), proposal-equivocation (`ProposalEquivocationEvidence`, `consensus.rs:2160-2286`), canonicalized/sorted/deduped; slash entry points `slash_equivocation` (`staking.rs:1673`), `_verified` (`1721`), proposal variant (`1821`), PQ variant (`1950`). **Downtime = canonical-QC-based**: proposer-chosen QC + adopt-side parity; `note_missed_heights` (`staking.rs:2058`), `slash_downtime` (`2042`), `apply_downtime_slashes` (`runtime.rs:5981`). Rates: equivocation **5%** (`EQUIVOCATION_SLASH_BPS`, `staking.rs:232`), µQC equivocation **100%** (`234`), downtime **0.1%** (`236`) after **42** missed heights (`DOWNTIME_MISS_THRESHOLD`), ≥500 heights between repeat hits (`DOWNTIME_PENALTY_COOLDOWN`). Record-once equivocation ledger (`consensus.rs:2358-2380`). |
| Light clients | First-class: `x/ibc` light clients (Tendermint headers + validator-set bisection), `verifySkipping`, misbehaviour detection; light-client-attack evidence type exists. | State-sync + Aptos light-client proofs via state checkpoints/Merkle proofs; timestamped checkpoints for recency; fullnode-gated sync. | Checkpoints + effects certificates; any holder of an effects cert can convince anyone (no full epoch wait); parallel cert sharing / third-party distribution. | Old: RPC `confirmed`/`finalized` + vote-tower roots. New: block-footer finalization certs (Geyser `notify_block_footer`), `getAgGenesisCert`; BLS certs verifiable with validator keys. | Altair sync-committee light client (512 keys + aggregate BLS per header); bootstrap from weak-subjectivity checkpoint; EIP-8390 (2026 draft) proposes removing it for ZK proofs. | **Wired-in, quorum-anchored** (`light_client.rs:1-80`): node keeps anchor at own finalized head (precommit-QC header); sync accepts peer chains only extending a QC anchor (`verify_synced_blocks_against_anchor`); serves `stell_getFinalizedCheckpoint/Header`; CLI `stellereum light-client --from --verify` requires **out-of-band validator set** (trust anchor stated explicitly). **Precommit-QC-only finality** (prevote QC refused); header root = state *before* the block (`H` commits `H-1` state, proof served at `H+1`). Exclusion + MMR epoch roots (500) available (`01_ARCHITECTURE_OVERVIEW.md`). |
| Validator UX (bonding / unbonding) | Bond any amount, top-180 by stake active; **21 d unbonding** (illiquid, no rewards, still slashable); redelegate immediate; 5% min commission; jail/un-jail + tombstone states. | Delegation pools; 1M APT min to activate; **recurring lockup ~14 d** (governance-set; unlock request → withdrawable at lockup end, auto-renew); commission on unlock; rewards auto-compound/epoch (~2 h). | Stake → pool; changes apply at **epoch boundary (~24 h)**; withdraw/unstake effective next epoch; commission changeable anytime (check before staking); low minima post-SIP-39 (voting-power units, not raw SUI). | Stake accounts; **warmup/cooldown ~1 epoch each (~2 d)**, 9%-of-stake/epoch rate limit both directions; re-delegation ≈ 2 epochs dark; lockups optional; commission settable; delinquency = missed rewards only. VAT 0.8 SOL/epoch + BLS key (Alpenglow). | **32 ETH** deposit; activation/exit **queues** (churn caps; ~57.6k ETH/d); effective-balance cap 32 (pre-Electra); partial withdrawals auto-swept; exit → withdraw after finality + delay. | **Self-bond-gated set**: power = self-bond + delegated; only self-bond elects (`MIN_VALIDATOR_BOND` = 1000 STELL, `staking.rs:59`); NEW bonds need MIN+100 STELL buffer (`STELL_MIN_BOND_BUFFER`, `staking.rs:61-75`); **~2 d unbonding** (`UNBONDING_PERIOD_SECS`, `230`); unlimited concurrent batches; top-up allowed; **H+1 activation** for every mutation (`staking.rs:21-23`); `bond` (`890`) / `add_bond` (`974`) / `unbond` (`1107`) / `delegate` (`1147`) / `undelegate` (`1209`) / `withdraw` (`1307`); **commission immutable after set** (default 10%, `256`; change needs exit-window opcode, not shipped); delegations ≥1 STELL (`227`); emission cap 350B (`226`); single-shard stake for now (shard-1 PARKED, spec 04). |
| Known liveness failure modes | ≥1/3 offline ⇒ halt (no finality, no fork); proposer offline/partition ⇒ round-skip via timeouts; app-level `ProcessProposal` rejects ⇒ nil-storm; evidence storms; long-range / amnesia handled by locks + evidence TTL. | Dead/faulty leaders (reputation demotes, but each costs timeouts + TC); Ditto fallback absent in prod path; leader-key concentration (top pools elected more); performance-scaled rewards hide marginal nodes until they matter. | No-leader ≠ no-liveness-issue: crashed/slow anchors stall that sub-DAG (Mysticeti tolerates better via multi-anchor, still waits); 3-fault tests: HotStuff → few-100 TPS/15 s+, DAG holds ~70k TPS/8–10 s (Bullshark) vs sub-second (Mysticeti-C). | Tower: "halting with epsilon stake" (ETH-Zurich 2024): tiny stake exploits lockouts to stall finality without fork; vote-tx bloat (~500 KB/slot, ~3/4 of tx volume); delinquency without burn (32 delinquencies/30 d observed, only opportunity cost). Votor open items: 20%+20% resilience (weaker than 33%), MEV/multiple-leader questions, slashing still missing. | 1/3+ offline/attacking ⇒ no finality until inactivity leak bleeds them below 1/3 (fast in exercises, slow/painful live); balancing/bouncing/avalanche on fork choice (mitigated by proposer boost + latest-message rule, ideal-condition proofs only); 50% split ⇒ social recovery. | **Observed, with fixes named**: (a) unanimity fragility — 3/3 quorum meant any split stalled (`PROPOSER_REWORK.md:12`); since moved to N=4, 2f+1 (spec 04). (b) stale-chase under slow members — 250 ms link + 1-vCPU ticks vs 3.5 s base ⇒ ~1 QC/5 min, 12k rounds burned at one height; mitigations: `MAX_ROUND_ADVANCE_PER_MESSAGE=1` (`consensus.rs:168`), `ROUND_LOOKBACK=8` (`181`), `MAX_SYNC_JUMPS_PER_ROUND=8` (`3755`), future-rule +1/round jumps, polka ledger (`4051-4058`), network-anchored scan + re-phase window 4096 (`3787`), deadlock breaker ≤65,536 rounds corroborated (`3770`, `4889`). (c) #285027/#288000-class parks (prevote-QC-but-no-precommit; non-atomic commit fork) ⇒ polka ledger + atomic-commit-with-undo + `adopt_committed` H+1 uniformity (`runtime.rs:7522`) + `DIVERGENCE` watchdog tag. (d) nil-storms: breaker K=3 (`3826`), `peer_alive` nil-withhold, 318 s deadlock breaker (`PROPOSER_REWORK.md:32`). Residual: WAN RTT + slow-member physics; straggler-grace sim-only, not production. |

## 2. OUR design in the same shape (ground truth, file:line)

- **Rounds/votes/locks**: height-scoped `HeightConsensus`, steps Propose→Prevote→Precommit→Commit
  (`consensus.rs:3906-3934`). One live proposal/round, wrong-proposer rejected, equivocating
  re-proposal refused (`3971-3994`); `has_live_proposal` gates voting (`4002`). `decide_prevote`
  honors lock (locked value or nil, `4008-4021`); `decide_precommit` echoes the prevote-QC target
  (`4024`); decision additionally requires same-round prevote+precommit agreement AND lock
  compatibility, with monotonic lock-round (`4436-4497`). Cross-round vote-carry explicitly rejected
  as fork-unsafe (`PROPOSER_REWORK.md:74-99`, `consensus.rs:3874`).
- **QC**: `QuorumCertificate{height,round,kind,block_hash,signatures}` (`2806-2812`); power counted
  over verified genuine signers only (`1431`); quorum `floor(2W/3)+1`, fail-closed on empty set
  (`1389-1405`). Batch-then-per-sig verification, 4096-signer DoS cap (`2817-2916`,`192`).
- **Timeouts/jumps**: base compiled (`FROZEN_ROUND_TIMEOUT_BASE_MS = 3000` ms since
  ruleset v2; the old env knob is removed; the historical live unanimity stand ran 20000 ms,
  `PROPOSER_REWORK.md:15`), `deterministic_round_timeout_ms = base + min(500·round, 10s) +
  min(500·missed_streak, 5s)`; node-loop effective timeout mirrors it;
  DOWN-PROPOSER fast path 800 ms; nil at ~2×; tick floor 50 ms; peer-round sync
  capped (+1/message, ≤8/jump window, ≤8 jumps/round); only QC/TC-like evidence
  advances rounds (no pure timer jumps — cf.
  ATOM-Quantum-style invariant; ours via vote-anchored `sync_round_to` + view-change).
- **Committees/sortition**: full-set µQC at N≤128 (`MICRO_COMMITTEE_MAX_SIZE`);
  network-anchored µQC threshold
  (`844-883`); parent-hash-seeded BLAKE3 sortition (`885-949`) with documented grinding residual
  (proposer chooses parent bytes; mitigation = network-majority threshold, not ungrindability);
  VRF-gated upgrade path default-off.
- **Crypto**: Ed25519 votes bound to `(chain-id, height, round, kind, hash)` domain `V2`
  (`1563-1586`); BLS aggregate + Falcon-512 envelopes ride inside vote/QC bytes, layout-identical,
  flags-off default (`199-332`); Falcon = FIPS-206 verify-only, test backdoor removed (`374-391`);
  BLS has **no proof-of-possession** (spec 02 — structural gap); chain-id frozen per process
  (`48-69`); legacy unbound envelopes height-gated (`100-147`).
- **Validator economics**: see §1 UX row + `staking.rs` refs above. Downtime accounting from
  committed QCs only (local and adopt paths agree, `runtime.rs:4386,4756,5073,7795-7801`).
- **Sync/light**: §1 light-client row; catch-up = snapshot + `stelops` checkpoint verify (gap-0),
  lockclear on anchor-trap, hourly prune (spec 04).
- **Sharding**: single active shard; workchain shard-1 PARKED (empty, no user txs — unpark needs
  funded demo + serving RPC, spec 04).

## 3. GAP list — what every mature BFT has that we lack (ranked for testnet)

1. **Multi-node, adversarial liveness proof under f≥1.** Cosmos/Ethereum/Aptos/Sui all ship
   timeouts + view-change/TC + reputation/inactivity-leak and *measure* degraded-mode finality.
   We have the mechanisms (backoff, breaker, re-phase, nil-breaker) but the binding
   straggler-tolerance fix is **sim-only** (`PROPOSER_REWORK.md:200-210`); live evidence is
   single-stand anecdotes (3-node unanimity, 250 ms link). Testnet needs: N≥4 WAN, 1 slow + 1
   down member, published finals/view-change/stale-share curves — else every other gap is moot.
2. **Evidence gossip + slashing execution that actually fires on testnet.** Cosmos has
   `x/evidence` + TTL + tombstone; Ethereum pays proposers to include slashings. Ours records
   + verifies + canonicalizes equivocation/downtime (`consensus.rs:1856-2286`,
   `runtime.rs:5981`) but needs a testnet drill: inject double-vote + downtime, show the 5% /
   0.1% burns, ejection below MIN, and the H+1 power change — with explorers displaying it.
3. **Light-client + validator-set rotation story a third party can verify.** IBC/Tendermint,
   Altair sync committees, Sui effects certs, Votor footers all let *someone else* check us.
   Ours is wired (`light_client.rs`, RPC, CLI) but trust-anchors on an out-of-band set with no
   rotation/epoch protocol, no IBC-style bisection, no weak-subjectivity checkpoint convention.
   Testnet needs: published set endpoint, rotation rule, and a documented "how to verify us from
   genesis + checkpoints" page.
4. **Validator UX around failure: jailing/un-jailing, redelegation, commission changes.**
   Cosmos: jail + `unjail` + redelegate + 5% floor commission. Sui/Aptos/Solana: epoch-boundary
   moves with clear dark windows. Ours: unbonding works (~2 d) but commission is **immutable**,
   no `unjail` flow, no redelegate fast path, bare-MIN bonds one downtime-slash from ejection
   (buffer warns but does not protect). Testnet operators will hit all four.
5. **Fork-choice + fork-alarm runbook.** Ethereum: LMD-GHOST + proposer boost + inactivity leak.
   Solana: bank-id/certified-fork rule. Ours: same-round QC agreement + `DIVERGENCE` watchdog tag
   (spec 04) but no published "two-finalized-heads: page whom, keep which, how to rejoin" runbook,
   and no automatic leak to recover 1/3-down finality (by design — unanimity history shows we
   halt instead). Write the runbook before inviting external stake.
6. **BLS proof-of-possession.** Spec 02 flags it structural; mature stacks (Altair committees,
   Votor BLS certs) require PoP/registration (Solana: BLS key registration + admission ticket).
   Without it, rogue-key aggregation is a known foot-gun on the BLS path.
7. **VRF leader/committee privacy + grinding resistance.** Ours documents the parent-hash
   grinding residual openly (`consensus.rs:910-928`); VRF wiring is phase-1, default-off
   (spec 02/04). Cosmos RANDAO-rotation / Aptos reputation / Sui multi-anchor all reduce the
   "DDoS the next proposer" surface further than we do today.
8. **Fee-market + mempool DoS parity.** Mature chains bound proposal size/time
   (CometBFT `PrepareProposal` timeouts, Aptos Quorum Store, Sui reference-price + tallying).
   Ours has VEL prebuild + verify-once caches and stream caps that "shed slow peers"
   (spec 04) — good, but no published overload/latency SLO for proposal construction under full
   mempools.

## 4. What we have that's unusual — honest assessment

- **Post-quantum vote/QC envelopes (Falcon-512, FIPS 206) + hybrid paths.** Genuinely rare:
   neither Cosmos, Aptos, Sui, Solana, nor Ethereum puts PQ signatures on the consensus vote
   path today. Honest caveats: 897-B keys / 666-B sigs bloat QCs (64-seat µQC ≈ 42.6 KB noted in
   `consensus.rs:814`); pure-PQ enforcement + HSM story incomplete (remote signer is
   Ed25519-only per its own header); BLS-without-PoP + PQ-without-rotation-audit means the
   exotic paths widen rather than narrow the audit surface. Keep flags off until a PQ-only
   testnet drills them.
- **Single-shard PARK (workchain shard-1 empty).** Pragmatic, not principled: it removes an
   entire cross-shard fault surface from the live deployment. Note the 2PC itself is now
   **active from genesis** (`XPC_ACTIVATION_HEIGHT = 0`, `xshard2pc.rs:146`) and tested by the
   two-shard soak; the live chain remains single-shard because shard-1 is parked, not because
   the protocol gate is off. Cost: every "sharded" claim is currently single-shard; unparking
   needs funding + serving RPC, not just a flag flip.
- **Downtime-as-deterministic-input (canonical QC evidence, both propose + adopt paths).**
   Unusual in a good way: downtime accounting derives from committed QCs every node replays
   identically, instead of local wall-clock counters. Residual: thresholds (42 misses, 500-height
   cooldown) are tuned, not proven; no inactivity-leak equivalent — a truly-down member still
   parks the chain by quorum arithmetic, which is honest but is exactly the failure mode
   mature chains engineered around.
- **Deterministic, auditable proposer schedule with published bug history.** Hash-slot + GCD +
   explicit sort is simpler to audit than RANDAO/reputation pipelines, and the two fixed monopoly
   bugs are documented in-code. Cost: full lookahead (DDoS-able proposer) + grindable parent hash
   — accepted for testnet, must be revisited (VRF) before open stake.
- **Stale-chase diagnostics as first-class artifacts.** `PROPOSER_REWORK.md` + sim harness with
   pasted counters (stale share, waste, jumps, grace extends) is better evidence practice than
   most testnet comparisons get. It is still *simulation*: flat timeouts, no partitions, no
   nil-storms, no lock divergence (§4 limits) — do not cite sim finals-rate as chain TPS.

## Sources (external, 2026)

- Tendermint/CometBFT spec: propose/prevote/precommit, +2/3, locking, round-robin proposer.
- Cosmos Hub validator FAQ (gaia v28.3.1, 2026-10-15): 180 validators, 21 d unbond, 5% double-sign + tombstone, 0.01% downtime + 10-min jail, ~5.7 s blocks, 5% min commission.
- AptosBFT/Jolteon: 2-chain commit, Order-Votes 5→3 delays, reputation leaders, Quorum Store; staking: ~2 h epochs, ~14 d recurring lockup, 1M APT min, **no slashing**, rewards-only penalties, ~0.9 s finality.
- Sui/Mysticeti: uncertified DAG, 3-message-delay commits, multi-anchor, owned-object fast path; p50 ~400 ms prod (650/975 ms @137 validators), ~24 h epochs, tallying-rule reward slash, voting-power-capped set.
- Solana Tower→Alpenglow: Tower 32-vote lockouts, 12.8 s rooted, no programmatic slashing, epsilon-stake halting paper; Votor live epoch 1064 / slot 459,653,000 (2026-10-21): 80%/60% certs, ~150 ms target, BLS certs ~1 KB, 0.8 SOL/epoch VAT, Rotor unscheduled.
- Ethereum Gasper: 12 s slots, 32-slot epochs, RANDAO proposers, LMD-GHOST + Casper-FFG, ~13–19 min finality, 4-epoch inactivity leak, 32 ETH + queues, Altair 512-member sync committees, weak subjectivity, 36-d slashing with correlation penalty.
