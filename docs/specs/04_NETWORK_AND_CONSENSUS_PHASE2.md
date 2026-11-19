# 04 — Network & Consensus (HDAE Phase-2, code truth)

Verified on the 2026-11-18 tree (base HEAD `0fdf1eefc` plus the day's in-flight
edits; line numbers match that tree), **after** the module split:
`consensus.rs` is `consensus/{mod,engine,types,sortition,qc_split}.rs` and
`runtime.rs` is `runtime/{mod,apply,consensus_step,anchors,lanes,cluster,mev_sync}.rs`.
Every `file:line` below was re-grepped on that tree; a claim that could not be
re-verified is marked STALE with the module directory to read instead.

Sources: `stellereum/src/consensus/`, `consensus_net.rs`, `network.rs`,
`sync.rs`, `mempool.rs`, `staking.rs`, `cn_vrf.rs`, `minroot_vdf.rs`,
`node/consensus_driver.rs`, `zkml.rs`.

## 1. BFT round structure

- Steps `Propose → Prevote → Precommit` via `HeightConsensus`
  (`consensus/engine.rs:989`); `decide_prevote` (`:1395`),
  `decide_precommit(prevote_qc)` (`:1411`); `proposer_for(height, round)`
  (`consensus/types.rs:997`).
- Quorum power: `ValidatorSet::quorum_power()` (`consensus/types.rs:789`),
  `quorum_reached` (`consensus/engine.rs:690`), `quorum_target` (`:698`);
  formula `floor(2n/3)+1` (`consensus/sortition.rs:24`, `consensus_quorum_min`).
  FREEZE: the value is the BFT safety curve; no env knob ever existed.
- µQC — **the rule the code enforces** (`consensus/sortition.rs:89,113,155-164`,
  verification at `consensus/types.rs:1849-1861` / `micro_cert_meets_quorum` (`:2170`)):

  - committee size cap `MICRO_COMMITTEE_MAX_SIZE = 128` (`sortition.rs:89`),
    seats = `min(N, 128)` (`micro_committee_size`, `:113`);
  - power rule `pq_micro_required_power` (`:155-164`):
    `required = max(floor(2*W_committee/3)+1, floor(2*W_network/3)+1)`;
  - a zero-power committee fails closed (`u64::MAX`, `:156-158`);
  - `mixed_quorum_pair_safe` (`:281`) is the fail-closed cross-level check
    called from µQC verification.

  Code rationale (`sortition.rs:126-150`): the old network
  term `floor(W_network/2)+1` gives `2T − W ∈ {1, 2}`, so **any** `B_w ≥ 2`
  breaks it — two conflicting 51-power certificates (32 Byzantine + 19 honest
  each, all-Byzantine intersection) both pass `51 = floor(100/2)+1`.
  "Strict majority does NOT imply quorum intersection; only `2t − W > B_w`
  does", so "the network term is therefore the same BFT curve as
  `consensus_quorum_min`: `floor(2·W_network/3)+1`." A committee that cannot
  reach the network-anchored floor is REFUSED rather than accepted at a
  weakened threshold — the µQC is an accelerator, the full network path stays
  authoritative (`:145-149`). The 128-seat cap is sized for capture resistance
  (`k ≥ 105` for `2^-40` at `α = 1/3`; `:75-88`), not bandwidth.
- Certificate markers: `PQ_UQC_MARKER_ID = [0xFD; 32]` (`consensus/types.rs:383`),
  `PQ_QC_MARKER_ID = [0xFE; 32]` (`:377`); signer-list cap
  `MAX_COMMIT_CERT_SIGNERS = 4_096` (`:198`). There is **no BLS QC marker** in
  the tree (the BLS path and `bls.rs` are deleted; FULL-PQ).
- Sortition: canonical draw domain `STELL_SORTITION_V5`
  (`consensus/sortition.rs:425`), `derive_sortition_committee` (`:404`).
  Parent-hash draw is the live election; the residual grindability is
  documented on the draw and mitigated by the network-anchored quorum.
- CN-VRF v3 (gated OFF): `CNVRF_V3_ACTIVATION_HEIGHT = u64::MAX`
  (`consensus/sortition.rs:552`), `CNVRF_V3_EPOCH_LEN 7_200` (`:556`, compile-
  time-pinned to `cn_vrf::EPOCH_LEN`), `CNVRF_V3_DRAW_DOMAIN` (`:561`),
  `CNVRF_V3_PROPOSER_DOMAIN` (`:564`), `cnvrf_v3_proposer_seed` (`:601`),
  `cnvrf_v3_beacon_draw_committee` (`:619`). Fed by `CommitCarrierV3`
  (`V3_COMMIT_LOOKAHEAD_BLOCKS`, `cn_vrf.rs`), off-tick `VdfLane`
  (`runtime/anchors.rs:265,274,744`) evaluating checkpointed MinRoot
  (`minroot_vdf.rs`), deterministic `epoch_raw_seed` fallback, and
  non-vote-resettable abort slashing in `staking.rs` (see
  `docs/PQ_CN_VRF_SPEC.md` §7). This section is **STALE** if read as live: the
  gate is `u64::MAX`, so every branch above is dormant.

## 2. Timeout ladder

- `deterministic_round_timeout_ms(base, round, missed_streak)`
  (`consensus/sortition.rs:719`): multiplicative backoff
  `DETERMINISTIC_BACKOFF_FACTOR = 2` (`:650`) capped at
  `DETERMINISTIC_BACKOFF_CAP_MS = 10_000` (`:656`), plus `500 ms` per missed
  proposer capped at `5_000`; base is `FROZEN_ROUND_TIMEOUT_BASE_MS = 3_000`
  (`:717`). There is **no per-node env override** for the base (the old
  `STELL_ROUND_TIMEOUT_MS` is gone); the value MUST match on all validators.
- Zero wall-clock inputs: the function reads only `base_ms`, `round` and the
  deterministic proposer missed-streak (doc block `:694-712`).
- Nil-breaker `NIL_CIRCUIT_BREAKER_K = 3` (`consensus/engine.rs:1270`), applied
  when `consecutive_nil_rounds >= K` (`:2109`).
- Tick floor: `STELL_MIN_BLOCK_MS` pacing (`node/consensus_driver.rs:892-898`);
  round-zero propose cap 650 ms (`node/consensus_driver.rs:3647`).

## 3. Lock rules

- Lock refuses a conflicting block at `r <= locked_round`
  (`consensus/engine.rs:1618-1621`); a newer polka unlocks only when
  `polka_round > locked_round` and the value differs (`:1713-1716`);
  `decide_prevote` prevotes nil when the proposal differs from the lock
  (`:1395-1407`).
- Nil semantics: a nil quorum is NOT a polka and never masks one
  (`consensus/engine.rs:1726-1745`); `observed_polka` records the newest polka
  the node has seen, independent of the local round (`:1123-1128`).

## 4. QC shape

- `QuorumCertificate { height, round, kind, block_hash, signatures }`
  (`consensus/types.rs:1605-1611`); unified verify (`:1617`): anti-DoS signer
  cap first (`MAX_COMMIT_CERT_SIGNERS`, `:198`), then the PQ/µQC envelope path
  (`:1849-1861`). FULL-PQ only: non-post-quantum entries are rejected, there is
  no classical/BLS fallback (`:1859-1861`).
- Vote preimage: `vote_sign_bytes(height, round, kind, block_hash)`
  (`consensus/types.rs:1111`); domains `VOTE_FALCON_MAGIC` (`:216`) and
  `QC_PQ_MAGIC` (`:393`).
- Evidence caps: 64 equivocation evidences per block
  (`consensus/engine.rs:108`), 8 proposal-equivocation evidences (`:339`),
  each with its own byte cap (`:102,:332`).

## 5. Sync / catch-up

- Missing-block scan `collect_missing_blocks` (`sync.rs:134`); anchor verify
  `verify_snapshot_anchor_with_sets` (`:398`) + test-only single-set wrapper
  (`:510`); tail window 3 (`SNAPSHOT_ANCHOR_TAIL_WINDOW`, `:555`); snapshot
  set-binding check `check_snapshot_set_binding` (`:1197`).
- Retry backoff: base 100 ms (`FETCH_RETRY_BASE_BACKOFF_MS`, `:1600`), max
  1000 ms (`:1602`), jitter cap 100 ms (`:1612`).
- Scheduling: event-driven. A verified peer message (or head pointer) above
  our tip schedules the next attempt; the reactive floor is 500 ms, the
  `STELL_CATCHUP_INTERVAL_MS` backstop defaults to 30 s, and a node at tip
  skips the probe. A pass is bounded by `STELL_CATCHUP_BUDGET_MS` (default
  250 ms).
- Gap-0 / checkpoint invariants: no `GAP_0` const exists in the tree; the
  gap-adjacent consts are `RETRO_SKIP_BEHIND_GAP = 100` (`sync.rs:1856`) and
  `LIVE_ADOPT_GAP_THRESHOLD = 16` (`:1976`). Resync depends on the
  snapshot-anchor verification above.
- F5 set-at-height: live paths use the `*_with_sets` entries; the single-set
  `validate_sync_chain` / `validate_sync_chain_for_shard` are TEST-ONLY compat
  entries (documented on the functions, zero production callers).

## 6. Transport: dial/backoff, accept hardening, caps

- Topics/caps: `CONSENSUS_TOPIC_BASE` (`consensus_net.rs:47`),
  `TX_TOPIC_BASE` (`:51`); 32 MiB consensus (`MAX_CONSENSUS_MSG`, `:75`) /
  1 MiB tx (`MAX_TX_MSG`, `:78`); batch 32 items (`:85`) / 512 KiB (`:92`);
  vote send-dedup TTL 200 ms (`VOTE_SEND_DEDUP_TTL_MS`, `:154`); join budget
  500 ms (`BROADCAST_JOIN_TIMEOUT_MS_DEFAULT`, `:773`); send timeout env
  `STELL_SEND_TIMEOUT_MS` (`:745`).
- Accept path: `accept_inbound` (`network.rs:2948`, called `:2932`); message
  cap `MAX_CROSS_SHARD_MSG 4 MiB` (`:2353`); block wire cap 32 MiB
  (`MAX_WIRE_BLOCK_BYTES`, `:2358`); endpoint table 512 records
  (`:3431`), backoff threshold 5 (`:3437`); stream-shed/receiver-drop =
  superseded-vote drop `SUPERSEDED_ROUND_LAG = 2` (`consensus_net.rs:162`),
  predicate `is_superseded_vote` (`:194`), batch coalesce `coalesce_for_send`
  (`:203-219`); proposals/commits/batches are never droppable.
- Replication store: 5 s timeout (`REPL_STORE_TIMEOUT_MS_DEFAULT`,
  `network.rs:4311`), 3 attempts (`:4315`), retry base 200 ms (`:4317`) and
  cap 2 s (`:4319`), jitter max 250 ms (`:4323`).
- Reputation: no peer down-score table in `stellereum` `network.rs` (comment
  `:2119-2121`: mismatch is logged, the hook is named for a future system).
  Per-peer reputation lives in infnode
  (`infnode/crates/infnode/src/reputation.rs:1-30`: score clamp,
  soft-throttle + temp-ban at the accept gate).

## 7. Eclipse-resistant discovery — WIRED (not planned)

- Status 2026-11-02: WIRED in `stellereum/src/network.rs` (not a plan item).
  Entry: `pinned_identity_set` (`:3455`, ONLY trusted source — Falcon `pq-pub`
  pinned + TLS-verified) → `filter_discovered_to_pinned` (`:3474`, drops unknown
  pq-pubs) → live wrapper `discover_peers_filtered` (`:3667`).
- Bounds: `MAX_ENDPOINT_RECORDS 512` (`:3431`, healthy-network headroom +
  `PeerEndpointTable::enforce_cap` `:3630`), `ENDPOINT_BACKOFF_THRESHOLD 5`
  (`:3437`, `backed_off` `:3531`), endpoint record shape (`PeerEndpoint`
  `:3490-3503`: endpoint/last_seen_ms/consecutive_failures; dial order
  `preferred_order` at `:3608-3620`).
- Rationale comment (`:3412-3425`): attacker-chosen identities are the eclipse
  first step; the filter is the containment.
- Tests (live, not sim): `infnode/crates/infnode/tests/eclipse_tests.rs` —
  `eclipse_flood_dials_honest_unaffected_attacker_throttled` (`:240-407`),
  `eclipse_sybil_burst_per_ip_and_per_identity_limits` (`:419+`); per-IP
  bounding proven via the reputation suite.

## 8. Transport caps restated (no new consts this pass)

- Consensus/tx caps + batch + vote-dedup + join/send budgets are exactly the
  §6 table (`consensus_net.rs:47,51,75,78,85,92,154,745,773`;
  `MAX_CROSS_SHARD_MSG` `network.rs:2353`; replication
  `network.rs:4311,4315,4317,4319,4323`). No new transport consts landed;
  stream-shed remains superseded-vote drop
  (`SUPERSEDED_ROUND_LAG 2` `consensus_net.rs:162`, predicate `:194`).
