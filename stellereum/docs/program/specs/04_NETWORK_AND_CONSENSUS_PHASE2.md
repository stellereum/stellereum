# 04 — Network & Consensus (HDAE Phase-2, code truth)

Sources: `stellereum/src/consensus.rs`, `consensus_net.rs`, `network.rs`,
`sync.rs`, `mempool.rs`, `staking.rs`, `main.rs`, `zkml.rs`.

## 1. BFT round structure

- Steps `Propose → Prevote → Precommit` via `HeightConsensus` (`consensus.rs:3905-3934`);
  lock field init `locked: None` (`:3916`); proposer accessor `:3966`,
  `proposer_for(height, round)` (`:1476`); single-value rule `:3981-3989`.
- Decide: `decide_prevote` (`:4008`), `decide_precommit(prevote_qc)` (`:4024`).
- Quorum power: `quorum_power()` (`:1389`), `quorum_reached` (`:2472`),
  `quorum_target` (`:2477`); formula `floor(2n/3)+1` (`:766-770`).
- µQC: committee cap 64 (`:817`), power rule max(2/3 committee, 1/2 network+1)
  (`:873-882`); markers `PQ_UQC 0xFD` (`:476`), `PQ_QC 0xFE` (`:470`),
  `BLS_QC 0xFF` (`:221`); signer cap 4096 (`:191`).
- Sortition: seed `BLAKE3(STELL_SORTITION_V5 || parent || h || r)` (`:1052-1064`);
  VRF-gated variant (`:1080-1086`) consuming registry-verified output only.

## 2. Timeout ladder

- `deterministic_round_timeout_ms(base, round, missed_streak)` (`:3891-3903`):
  backoff 500/round cap 10000 (`:3834,:3840`), adaptive 500/miss cap 5000
  (`:3847,:3853`); base from `STELL_ROUND_TIMEOUT_MS` (`:3882-3883`, must match
  across validators); zero `Instant/SystemTime` inputs (`:3888-3890`); pinned
  example `timeout(3500,0,0)` (`:5187-5195`).
- Nil-breaker K=3 (`NIL_CIRCUIT_BREAKER_K`, `:3826`, applied `:4677-4679`).
- Tick floor: 50 ms min-block pacing (`main.rs:974-978`); round-zero propose cap
  650 ms via `STELL_ROUND_ZERO_TIMEOUT_MS` (`main.rs:150-156`).

## 3. Lock rules

- Lock refuses conflicting block at `r <= locked_round` (`:4220-4225`); polka
  unlock allowed only when `polka_round > locked_round` (`:4312-4315`);
  precommit path honors lock (`:4470-4471`); re-lock invariant comment (`:4325-4381`).
- Nil semantics: nil quorum ≠ polka (`:4325-4335`); nil-breaker state
  (`:3725,:3930`).

## 4. QC shape

- `QuorumCertificate { height, round, kind, block_hash, signatures }`
  (`:2806-2812`); unified verify (`:2817-2833`): anti-DoS length cap first
  (`:2841-2843`), PQ path (`:2847`), pure-PQ classical refusal (`:2851-2854`),
  BLS aggregate power path (`:2861-2865`), Ed25519 batch/dedup after (`:2866+`).
- Vote preimage: `vote_sign_bytes` (`:1563`), chain-bound (`:1556-1561`); domains
  `VOTE_BLS_MAGIC` (`:204`), `QC_BLS_MAGIC` (`:223`), `VOTE_FALCON_MAGIC`
  (`:329`), `QC_PQ_MAGIC` (`:486`).
- Evidence caps packed under wire cap: 64 equivocations (`:1917`),
  8 proposal-equivocations (`:2148`).

## 5. Sync / catch-up

- Missing-block scan `collect_missing_blocks` (`sync.rs:134-184`); anchor verify
  `verify_snapshot_anchor_with_sets` (`:351`) + compat wrapper (`:456-469`);
  tail window 3 (`SNAPSHOT_ANCHOR_TAIL_WINDOW`, `:501`); set-binding check
  (`:1057`).
- Retry backoff: base 100 ms (`:1416`), max 1000 ms (`:1418`), jitter 100 ms
  (`:1428`); `fetch_retry_backoff_ms` (`:1644-1651`), jittered variant (`:1665`).
- Gap-0 / checkpoint-invariants: no `GAP_0` const exists in tree (grep zero
  hits); gap-adjacent consts are `RETRO_SKIP_BEHIND_GAP 100` (`sync.rs:1640`,
  used `:1721`) and `LIVE_ADOPT_GAP_THRESHOLD 16` (`:1731`); resync depends on
  snapshot-anchor verification above.

## 6. Transport: dial/backoff, accept hardening, caps

- Topics/caps: `CONSENSUS_TOPIC_BASE` (`consensus_net.rs:43`),
  `TX_TOPIC_BASE` (`:47`); 32 MiB consensus / 1 MiB tx caps (`:71,:74`); batch
  32 items / 512 KiB (`:81,:88`); vote-dedup TTL 200 ms (`:150`);
  join budget 500 ms (`:560-568`); send timeout env `STELL_SEND_TIMEOUT_MS`
  (`:526-532`).
- Accept path: `accept_inbound` (`network.rs:2911`, called `:2895`); message cap
  `MAX_CROSS_SHARD_MSG 4 MiB` (`:2344`); endpoint table 512 records (`:3352`),
  backoff threshold 5 (`:3358`); stream-shed/receiver-drop = superseded-vote
  drop `SUPERSEDED_ROUND_LAG 2` (`consensus_net.rs:158`), drop predicate
  `:185-191`, batch coalesce `:196-226`; proposals/commits/batches never
  droppable (`:155-157,168-171`).
- Replication store: 5 s timeout (`network.rs:4222`), 3 attempts (`:4226`),
  250 ms jitter max (`:4234`), backoff fn (`:4349-4357`).
- Reputation: no peer down-score table in `stellereum` `network.rs` (comment
  `:2112`: mismatch discarded + logged, hook named for a future system);
  per-peer reputation lives in infnode
  (`infnode/crates/infnode/src/reputation.rs:1-27`: score clamp, soft-throttle
  + temp-ban at the accept gate).

## 7. Eclipse-resistant discovery — WIRED (not planned)

- Status 2026-11-02: WIRED in `stellereum/src/network.rs` (not a plan item).
  Entry: `pinned_identity_set` (`:3443`, ONLY trusted source — ed-pub pinned +
  TLS-verified) → `filter_discovered_to_pinned` (`:3392-3400`, drops unknown
  ed-pubs) → live wrapper `discover_peers_filtered` (`:3585-3593`).
- Bounds: `MAX_ENDPOINT_RECORDS 512` (`:3352`, healthy-network headroom +
  `PeerEndpointTable::enforce_cap` `:3457-3473`), `ENDPOINT_BACKOFF_THRESHOLD 5`
  (`:3358`, `backed_off` `:3446`), endpoint record shape (`PeerEndpoint`
  `:3476-3455: endpoint/last_seen_ms/consecutive_failures`, prefer-success
  order `:3596+`).
- Rationale comment (`:3333-3340`): attacker-chosen identities are the eclipse
  first step; filter is the containment.
- Tests (live, not sim): `infnode/crates/infnode/tests/eclipse_tests.rs` —
  `eclipse_flood_dials_honest_unaffected_attacker_throttled` (`:240-407`,
  per-identity throttle, ban-escalation `:372-373`, no shared-IP blast radius
  `:407`), `eclipse_sybil_burst_per_ip_and_per_identity_limits` (`:419+`);
  per-IP bounding proven via reputation suite (header `:18-22`, G3 no-eviction-cap
  note honest about unbounded-distinct-churn).

## 8. Transport caps restated (no new consts this pass)

- Consensus/tx caps + batch + vote-dedup + join/send budgets are exactly the
  §6 table (`consensus_net.rs:43,47,71,74,81,88,150,526-532,560-568`;
  `MAX_CROSS_SHARD_MSG` `network.rs:2344`; replication
  `network.rs:4222,4226,4234,4349-4357`). No new transport consts landed;
  stream-shed remains superseded-vote drop
  (`SUPERSEDED_ROUND_LAG 2` `:158`, predicate `:185-191`).
