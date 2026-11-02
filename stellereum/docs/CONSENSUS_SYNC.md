# Consensus Sync / Catch-Up — Definitive Map

> Scope: how a lagging/fresh node learns the peer tip and replays to it.
> No live ops. All paths fail closed (refuse, never guess).
> File:line anchors are against the current tree (`src/`).

Terminology: `our_tip` = last finalized height in `rt.finalized`; `peer_height/hash` = advertised head; `expected_first_height` = `our_tip+1`.

---

## 1. DHT head pointers

**Where:** `src/network.rs:16-17` (`BUCKET_STELLEREUM_HEAD`), `76-79` (`head_name`), `37-50` (`EpochTag`), `696-760` (`publish_head`, `fetch_head` at `780`), `433-445` (`peer_head_is_ahead`), `418-421` (`head_publish_allowed`).

**Flow:**
- Head pointer blob name: `{epoch}_shard_{shard}_head`, epoch = first 8 bytes hex of genesis fingerprint (`EpochTag::from_genesis`). Prevents cross-chain contamination after wipe (comment `src/network.rs:26-31`: old chain's head survived wipe and a fresh node chased height-488 of a dead chain).
- Published every finalize + every ~30s probe; FOREVER TTL (`STELL_DHT_FOREVER_TTL_MS`, default 100y, `src/network.rs:196-200`); never pruned (`plan_retained_prune`, `src/network.rs:365-391`).
- `publish_head` only moves forward; refuses `height==0` and `height <= last_published` (`head_publish_allowed`, `src/network.rs:424-435`). Rationale in comments: shared head key is last-writer-wins, so a stale republish rewinds everyone's advertised head.
- Reader: `fetch_head(shard)` → `Option<(height,hash)>` (`src/network.rs:780`). One `fetch_sem` permit, single blob read.

**Triggers:** `try_catch_up` reads it every catch-up tick (`src/main.rs:2063`); `refresh_validator_set_from_fresh_snapshot` reads it to build domain candidates (`src/main.rs:1984`).

**Failure modes (live notes in code):**
- Miss / wrong epoch-shard / dead transport → `None`; throttled log every 30 misses: `"cannot read any peer head (miss {n}; peer may publish nothing yet, the epoch/shard may be wrong, or the transport may be down)"` (`src/main.rs:2064-2076`).
- Echo chamber: local manifest shadows peers on read, so node reads back its OWN head (`src/main.rs:2129-2133`). Hence `peer_head_is_ahead` strict `>` gate (`src/network.rs:437-445`).
- Last-writer-wins shared key, no author (`src/network.rs:417-421`, `src/main.rs:2129`).

## 2. `peer_hint` (proposal-observed head)

**Where:** `src/runtime.rs:539-540` (field `peer_hint: Option<(Height,BlockHash)>`), `5638-5642` (write in `on_proposal`), `974-975` (init `None`); gate `src/consensus_net.rs:3868-3894` (`proposal_hint_admissible`); receiver-loop note `src/consensus_net.rs:3165-3233`.

**Flow:**
- On accepted proposal for NEXT height, runtime records `(height, prev_hash)`-derived `(h.0)` as hint if `ph < h.0` (`src/runtime.rs:5641-5642`), but ONLY if `proposal_hint_admissible(block, validators)` = proposer signature verifies AND proposer has stake (`src/runtime.rs:5638`, `src/consensus_net.rs:3894`).
- `try_catch_up` prefers it over DHT: `dht_hint_head = [dht, peer_hint].flatten().max_by_key` (`src/main.rs:2078-2081`). Comment `src/main.rs:2057-2062`: DHT goes blind for minutes; proposals arrive every round on reliable direct path.
- Consumers: catch-up trigger (`src/main.rs:2098-2099`), net-budget sizing (`src/main.rs:3905-3911`), defer-for-live (`src/main.rs:3944-3949`), retro suppress gates (`src/main.rs:4070`, `should_suppress_retro_no_behind_peer` at `121-133`).

**Failure modes:**
- Deaf follower: node receiving no proposals never sets hint → both DHT+hint blind together (see §4).
- Forged hint DoS closed by G1 gate: unverified proposal must never plant hint, else "one junk envelope per tick keeps a node running loudly-failing DHT walks forever" (`src/consensus_net.rs:3868-3894`).

## 3. `try_catch_up` — orchestrator

**Where:** `src/main.rs:2050-2215`; tick driver `src/main.rs:3964-3998`; budget sizing `src/main.rs:3892-3921`.

**Trigger conditions (all must hold):**
- Tick: `last_catchup.elapsed() >= catchup_interval` (default 2000ms, `STELL_CATCHUP_INTERVAL_MS`, `src/main.rs:40-43,292-300,3701-3703`) AND `!has_pending_apply()` AND `!defer_for_live` (`src/main.rs:3964`).
- Inside: head = `max(dht, peer_hint)` if `peer_head_is_ahead(our, peer)` (`src/network.rs:443`, `src/main.rs:2098-2100`), else blind-QC-probe (§4). Refuse if `peer - ours > 1_000_000` (`src/main.rs:2140-2145`).
- Order: (a) stale-set repair if `is_validator_set_stale()` (`src/main.rs:2176-2183`); (b) snapshot-first if `gap > 100` (`src/main.rs:2184-2189`); (c) `walk_chain` (`src/main.rs:2191`); (d) if walk failed but snapshot landed, return boundary anyway (`src/main.rs:2194-2200`); (e) if still `gap > 100`, second snapshot + walk retry (`src/main.rs:2201-2213`).

**Tick budgets (three layers):**
- `net_budget`: `(2*round_timeout).max(5000ms)` near tip; `30_000ms` for gap 1..100; `180_000ms` (`SNAPSHOT_BUDGET_MS`) for gap >100 (`src/main.rs:3892-3921`). Comment: old 400ms budget meant 1-behind never healed; 5s budget killed snapshot attempts with zero progress.
- `catchup_budget`: `STELL_CATCHUP_BUDGET_MS` default 250ms wrapping the whole `try_catch_up` future (`src/main.rs:3969-3978`). Exhaustion → throttled `"catch-up skipped (network budget … exhausted)"` (`src/main.rs:3989-3998`).
- Inner fetch budgets: see §9.

**Failure modes (quoted):**
- `"peer claims height {peer}, we are at {ours}: refusing to walk"` (absurd gap).
- `"catch-up skipped (network budget of {}ms exhausted … peers unreachable or DHT too slow)"`.
- Doomed-walk retry: "node replaying 642 matching heights then failing at #643 with no in-band recovery, retrying the doomed walk every 2s forever" (`src/main.rs:2150-2152`) → snapshot-first ordering.
- SYNC TRAP N4 (stale-set verification trap, `src/main.rs:2164-2175`): node with outdated CONFIG set + fresh-looking ledger never sets stale flag → verifies everything against wrong set, refuses all, never repairs. Until fix: wipe + re-bootstrap.
- Live-adopt starvation avoided: defer logic + nil-vote announce after catch-up (`src/main.rs:4013-4042`: "catching-up node advances SILENTLY … retro help never flows … A nil vote at the fresh height breaks the silence").

## 4. Blind-QC-probe fallback

**Where:** `src/main.rs:2082-2128`; sidecar fetch `src/network.rs:1077-1106` (`fetch_block_qc`); name `src/network.rs:68-74` (`header_qc_name`, shard-scoped `{epoch}_hq_{shard}_{height}`).

**Trigger:** DHT+hint NOT ahead (`_ =>` arm at `src/main.rs:2102`). Probe `tip+1` QC sidecar: `fetch_block_qc(shard, our+1)`, require `qc.height == probe_h` and `qc.block_hash == Some(bh)` → adopt `(probe_h, bh)` with log `"blind-QC-probe: tip+1 … carries a QC sidecar; walking one height to adopt it"` (`src/main.rs:2103-2111`). Else return `None` (miss counter throttled every 30, `src/main.rs:2115-2127`).

**Why (live note `src/main.rs:2082-2097`):** "B sat one height behind a converged quorum (654 vs 655) retrying a no-op catch-up every 2s forever … a silent follower can never be rescued." Both signals go blind together: shared head key echo + deaf follower with no proposals. Probe is B-initiated DHT read (NAT-proof like `request_to`); present height-bound QC proves finality with no head advertisement. Walk below re-verifies everything; forged/stale sidecar refused as before. Liveness-only: no wire/quorum/apply change, bounded by caller budget.

**Failure modes:** miss/nil-QC/height-mismatch → `None` (fail-closed). `u64::MAX` tip saturates probe to tip itself; walk refuses on continuity (`src/main.rs:2134-2137`).

## 5. `walk_chain` validation

**Where:** entry `src/main.rs:2220-2559`; collect `src/sync.rs:129-183`; head anchor `src/sync.rs:595-619`; chain checks `src/sync.rs:648-864`; light anchor `src/sync.rs:31-108`; snapshot anchors `src/sync.rs:344-587`.

### 5a. Continuity + bounds

- Anchor: `(our_last_hash, expected_first = tip+1)`; genesis → `([0u8;32], 1)` (`src/main.rs:2233-2236`). Comment F3(c): anchoring on walked chain's own first height made height check tautology.
- Cap: `peer - expected_first > 256` → skip walk, defer to snapshot (`src/main.rs:2250-2256`). SYNC TRAP N6 note (`src/main.rs:2242-2249`): cap is load-bearing (unbounded WAN walk = DoS, do NOT raise); stranding when snapshot ALSO fails (N3/N4/N5) means fix N3–N5, not this bound. Log line `"gap … > 256 blocks; body walk skipped in favor of snapshot-sync"`.
- `collect_missing_blocks(head, last_finalized, 256, fetch_block)` (`src/sync.rs:134-183`, called `src/main.rs:2258-2263`): backward `prev_hash` walk, ancestor-first reverse; fail-closed on cycle / missing (`"block sync: missing block"`) / `len > max_len` (`"chain longer than max_len"`); **F3(a) hash check**: fetched body MUST hash to requested hash (`src/sync.rs:169-176`: poisoned DHT/malicious peer serving different body under key → reject at fetch boundary).
- `walked_head_anchor` (`src/sync.rs:599-619`, called `src/main.rs:2278`): walked tail MUST hash to advertised `peer_hash` AND sit at `peer_height` (F3(b): peer advertising above served chain refused, re-anchor on walked height never advertised height).
- Drop leading `<= tip` overlap; empty → `None` (`src/main.rs:2289-2297`).

### 5b. Per-block QC vs set-at-height

- `validate_sync_chain_for_shard_with_sets(blocks, expected_first, our_hash, |h| rt.validator_set_for_height(h), rt.shard_id)` (`src/main.rs:2312-2318`, impl `src/sync.rs:723-864`).
- Per block: height `+1` continuity; resolver `resolve_set(h)` fail-closed if `None` (`"no validator set known for height …"`); empty-set guard (`quorum_power == u64::MAX`); shard pin (`shard_id == expected_shard`, F8); parent link (`prev == parent_hash`); Falcon-aware proposer signature (`verify_proposer_signature`); attached `precommit_qc` must exist, `kind==Precommit`, `qc.height==h`, `qc.block_hash==compute_hash`, `qc.binds_to_parent(prev)` (chain binding — committee elected with committed parent); `qc.verify(set_at_h)` with signed/quorum accounting (`"lacks a validator quorum (carries X of Y required …)"`); proposer `proposer_matches_schedule(set_at_h, h, proposer, qc.round)` over rounds `0..=qc_round` (+4 tolerance) (`src/sync.rs:225-247` — re-proposed locked blocks keep original author).
- W10.5 rule: never live set; rotation mid-window must not re-verify old certs against new quorum (`src/sync.rs:666-674,756-761`).
- F5 limitation note (`src/sync.rs:636-647`): no height-indexed set snapshots; `StakingLedger::to_validator_set` reflects current bonded stake; conservative direction (rotated-out signers carry no power); residual closed by set-at-height threading + replay path.

### 5c. Light-client anchor + per-block root continuity

- After QC pass: `verify_synced_blocks_against_anchor_with_sets(light.clone(), blocks, set_at_h)` on a CLONE (live untouched, pure function) (`src/main.rs:2367-2380`, impl `src/sync.rs:68-108`). Each header → `LightHeader::of_block` (requires precommit QC, else `"carries no precommit quorum certificate; there is nothing to anchor on"`), then `apply_header_without_block_signatures` (finality-only: walked bodies carry only proposer block sig, strict sig quorum would refuse every legitimate tail — live 2026-10-25). Fails closed on gap/broken link/non-precommit/insufficient power/rollback/full window (`src/sync.rs:46-49`). Returns quorum-committed root; caller compares with locally computed root at last block (`src/main.rs:2410-2418`).
- Per-block `root_before == block.state_root` (header commits to state it BUILDS ON, checked before apply, `src/main.rs:2395-2403`) + divergence pin: after each apply, next block's `state_root` must equal our new root (`src/main.rs:2501-2513`: "observed live failure at #643 after 642 matching" → pinpoint not mystery).
- Transition parity: `precommit_qc` installed as `hc.precommit_qc`, body retained, `enqueue_block` persist, `apply_and_advance`, receipts/replication recorded (`src/main.rs:2444-2494`). Live note: tx-only apply forked nodes at #1303/#1304 when slashes/rewards moved balances; QC install matches adopt path. Equivocation slashing deferred on all paths (audit F4).
- Re-anchor: fresh `HeightConsensus::new(next, validators)` + `set_parent_hash(head)` (sortition entropy; unknown → warn + fail-closed committee, audit W6.4b, `src/main.rs:2518-2532`); broadcast `Committed{height,block,qc}` + `retro_publish_blocks(1)` + `persist_block_header` so lagging peers learn in place (`src/main.rs:2537-2557`).

### 5d. Tip-connected bypass

- If walk connects directly (`first.height==tip+1 && prev==tip_hash`), skip light-client continuity (`src/main.rs:2356-2390`): "OWN-FINALITY BYPASS (post-restart wedge repair)": node restarted on stale anchor, one behind converged quorum (#388560 vs #388561), rejected every chain on anchor gap ("leaves a gap") and could never adopt. Own tip is quorum-certified by construction → extension preserves safety. Log: `"walk connects to our finalized tip … anchor check bypassed (per-block QC + root checks still enforced)"`. Non-connecting walks keep full anchor path.

## 6. Snapshot sync + intervals

**Where:** orchestrator `src/main.rs:1601-1946`; proof `src/sync.rs:344-587`; state install `src/sync.rs:887-1108`; publish `src/network.rs:456-463` + persist paths; local snapshot cadence `src/main.rs:264-271` (`snapshot_interval`, `STELL_SNAPSHOT_INTERVAL` default 1000, min 50) + `src/storage.rs:1488-1602`; DHT retention §10; bootstrap gate `src/bootstrap.rs:1-60,222-251`.

**Trigger:** `gap > 100` (both `try_catch_up` at `src/main.rs:2185` and bootstrap `BOOTSTRAP_SNAPSHOT_GAP=100` at `src/bootstrap.rs:54`, mirroring comment). Entry refuses `peer <= ours+1` (`src/main.rs:1608-1610`).

**Probe loop (`src/main.rs:1644-1928`):**
- `TAIL_ANCHOR_GAP_THRESHOLD=50` (`src/main.rs:1626-1628`): `use_tail = genesis_anchored || gap > 50`. Beyond 50, full walk needs thousands of sequential header+QC fetches (10+ min weak link, never fits tick) while below tip−KEEP is pruned anyway; trailing window proves same unforgeable fact.
- `PROBE_STEPS=8` boundaries: `(peer/100)*100` downward, but `fetch_latest_snapshot` pointer first (snapshots land on worker timing like 78519/78620, %100 misses them all) if `ours < latest <= peer` (`src/main.rs:1649-1661`). Miss accounting (`miss_snapshot/miss_header`), storm-guard pacing `snapshot_probe_pace_ms(misses)` 20ms/miss cap 200ms (`src/sync.rs:1419-1425`, `src/main.rs:1680-1683` — 2026-10-13: 128 boundaries × fetches saturated 1-vCPU, 256-stream drops, self-exciting retries).
- Per boundary: `fetch_state_snapshot` → `fetch_head_hash(boundary+1)` → `fetch_block_header(... next_hash)` → height/hash match (`src/main.rs:1677-1724`); anchor fetch closure per height = `head_hash + header + qc → HeaderLink` (`src/main.rs:1745-1763`); then tail (`verify_snapshot_anchor_tail(boundary+1, validators, fetch)`, window `SNAPSHOT_ANCHOR_TAIL_WINDOW=3`, `src/sync.rs:457`) or full (`verify_snapshot_anchor(ours, genesis_root, boundary+1, validators, 1_000_000, fetch)`, `src/sync.rs:344-434`).
- `fast_sync_state(trusted_root, fetch_state, fetch_domain)` (`src/sync.rs:887-1005`): fetch all `SYNC_DOMAIN_KINDS` (domains/session/bridge/confidential/zkml/cross_shard/pq_keys, `src/sync.rs:877-885`) strictly sequential + yield; restore into EPHEMERAL engine, root check (`"poisoned snapshot rejected"` on mismatch); cross-shard replay coverage gate (absent blob + non-empty local replay → refuse; present but non-covering → refuse, audit F1 — silent split/double-mint); then install same bytes into target.
- Commit: `finalized.push((boundary, boundary_hash))` where `boundary_hash` comes from VERIFIED chain never peer `prev_hash` (audit W6.4b: poisoned head → fork + partitioned sortition, `src/sync.rs:293-318`, `src/main.rs:1849-1857`); `successor.prev_hash == boundary_hash` linkage recheck (`src/main.rs:1858-1872`); `hc = new(boundary+1)`, `set_parent_hash`, `refresh_validator_set_from_staking_checked` + stale-ledger guard (node C: ancient/empty ledger → observer, repair via set-only pull, `src/main.rs:1886-1902`); W10.5 heal `reanchor_light_client_at_snapshot` (`src/runtime.rs:1280`, called `src/main.rs:1910-1922`).
- Intervals/publish: local snapshots every `STELL_SNAPSHOT_INTERVAL` (default 1000, `src/storage.rs:1488`); DHT state snapshots every 100 heights, FOREVER TTL, never pruned (`src/network.rs:167-170`); domain kinds `SNAPSHOT_PUBLISH_DOMAIN_KINDS` (`src/network.rs:456-463`, superset rule); latest-pointer fail-closed publish (`src/network.rs:1204+` area per fetch path); bootstrap retry ladder = fetch backoff + jitter (`src/bootstrap.rs:259-261`).

**Failure modes (quoted):**
- `"REFUSING snapshot at {b}: trailing header proof failed: {e}"` / `"header anchor to our finalized head cannot be proven"`.
- `"snapshot anchor: span {} exceeds max_span (refusing unbounded walk)"`; `"no header published at height … cannot prove linkage"`.
- `"successor header does not link to the verified boundary block"` (forked view).
- `"snapshot at {b} rejected: {e}"` (root mismatch / replay gate).
- `"light-client re-anchor skipped: boundary block … not served"`; stale-set WARN → observer.
- SYNC TRAP N3 (`src/sync.rs:497-507`): committed-set drift behind rotation → every boundary refuses + body walk only 256 → node stranded; fix = pull CURRENT set via `refresh_validator_set_from_fresh_snapshot` and retry once (operator repair today: fresh domain snapshot in, re-sync).
- Residual admin trust F4 (`src/sync.rs:481-495`): fresh node verifies against CONFIG-supplied set; wrong genesis set syncs onto attacker fork undetectably → pin genesis/validator-set hash out of band.

## 7. `Committed` retro-publish (body availability)

**Where:** publish `src/network.rs:596-675` (`retro_publish_block[s]`, `RETRO_PUBLISH_PACE_MS=5` at `505`); pass `src/main.rs:2579-2676`; consts `src/main.rs:28-38` (`INTERVAL 30s`, `MAX_PER_PASS 128`, `DEPTH 4096`); skip gates `src/sync.rs:1496-1507` (`LIVE_ADOPT_GAP_THRESHOLD=16`), `src/sync.rs:1482-1487` (`RETRO_SKIP_BEHIND_GAP=100`), `src/main.rs:76-133` (suppress fns); catch-up announce `src/main.rs:2537-2557`.

**Flow:** live finalize publishes head pointer but historically never bodies → any 1-behind peer died with `"block sync: missing block"` (1007-block live failure, `src/network.rs:596-609`). `retro_publish_pass` walks `(published_upto+1 .. tip)` capped to last `RETRO_PUBLISH_DEPTH` and `MAX_PER_PASS` per pass, memory run first then disk (`spawn_blocking` over `hashes_at_height`), truncate forks to bound, publish via `TickLane` or inline, advance cursor even on failure (else one dead block stalls window forever, `src/main.rs:2671-2675`). Pacing 5ms + jitter ≤5ms (`src/sync.rs:1473-1480`) de-phases 30s-cadence publishers. BODY ONLY: never head/index (stale node must not rewind advertised head, `src/main.rs:2571-2574`).

**Suppress/skip (all local policy, never consensus):** skip while behind (`peer-ours > 100`, `should_skip_retro_while_behind`, `src/sync.rs:1485` — ~1800-behind node spawning 136 replicators per pass = pure flood); suppress when tip unchanged + inbound idle ≥60s (`should_suppress_retro_publish`, `src/main.rs:76-82`); suppress when no verified behind-peer within 120s and not behind (`should_suppress_retro_no_behind_peer`, `src/main.rs:121-133`); tip-8 supplement + walked-tip immediate publish cover the 1-behind case (`src/main.rs:2550-2555`).

## 8. Future-round jumps + budgets + corroboration

**Where:** caps `src/consensus.rs:149-181` (`MAX_ROUND_AHEAD=1000`, `MAX_ROUND_ADVANCE_PER_MESSAGE=1`, `ROUND_LOOKBACK=8`), `3755` (`MAX_SYNC_JUMPS_PER_ROUND=8`), `3766` (`MAX_DEADLOCK_JUMP=65536`); jump `src/consensus.rs:4516-4530` (`sync_round_to`), `4780-4797` (`observe_peer_round`), `4818-4830` (`note_peer_round`), `4841-4900` (`corroborated_peer_round`, `deadlock_breaker_target`), `4921-4961` (`apply_deadlock_jump`, `quorum_should_rephase`); runtime `src/runtime.rs:5423-5512` (`note_peer_vote_round`), `5519-5542` (`observe_peer_vote`), `5564-5599` (`check_deadlock_breaker`), `5854-5882` (verified-vote path).

**Rules:**
- Vote acceptance window: reject `round > ours+1000` (`src/consensus.rs:4030,4063`, test `vote_for_far_future_round_rejected`).
- Direct proposal path: at most +1 per message (`MAX_ROUND_ADVANCE_PER_MESSAGE`, `src/consensus.rs:4760`): live liveness bug — fresh node jumped to r57 in 100ms, proposer schedule diverged, healed partition unwedgeable.
- Vote-chase path: `sync_round_to` caps to `ours+8` per call, max 8 jumps per round (budget resets on view change, `src/consensus.rs:4526-4529`): old per-second budget put wall clock in state machine + allowed 32 rounds/s; new is deterministic and stricter (64 rounds/round ≈ <5/s live).
- `note_peer_vote_round` (runtime, the ONLY follower): records `peer_rounds[voter]=round` (counter only), then chases ONLY if vote verified member + height matches + `round > ours`: first sight of `(h,r)` follows once unconditionally (liveness — deferred-convergence deadlock if refused while holding proposal), continuing past one step needs corroboration by 2nd DISTINCT validator (same rule as breaker) and budget (`src/runtime.rs:5423-5512`); `last_followed_round` prevents re-chase; `observe_peer_vote` returns true only for verified member votes (`src/runtime.rs:5954-5963` — pre-fix bug bought +8 per fresh REJECTED vote).
- Deadlock breaker: fires after `STELL_DEADLOCK_TIMEOUT_SECS` (default 300) with no finalize (`src/runtime.rs:5548-5593`, `src/consensus.rs:4856-4900`); target = max corroborated peer round (≥2 reporters, `breaker_corroboration`), forward-only, ≤65536 jump (`apply_deadlock_jump` one-shot per timeout); re-phase widens scan instead of rewinding.

**Failure modes (quoted):** "runaway it guards is a burst … r9700, zero QCs" (uncapped jumps); "A r1550 vs B r318, each dropping the other's votes forever" (no peer-round counter); "A r1595 vs B r412, mutual deaf" (empty peer rounds → follow-up re-phase path).

## 9. Fetch paths (retries / timeouts)

**Where:** `src/network.rs:578-675` (body), `984-1106` (head-hash/header/QC: 10s timeout ×3 attempts, 300ms×attempt backoff), `1204-1610` (latest-pointer, state/domain snapshots: manifest 10s, chunk 20s ×6 retries, blob 300s, 2 blob attempts, serial resume); guards `src/sync.rs:1157-1253` (`FETCH_MAX_CONCURRENCY=8`, `SNAPSHOT_FETCH_MAX_CONCURRENCY=2`, `SNAPSHOT_CHUNK_TIMEOUT_MS=20000`, `SNAPSHOT_MANIFEST_TIMEOUT_MS=10000`, `SNAPSHOT_BLOB_TIMEOUT_MS=300000`, `SNAPSHOT_BLOB_ATTEMPTS=2`, base 100ms/cap 1000ms/jitter 100ms, `FETCH_BLOB_CHUNK_BATCH=4`, `LARGE_BLOB_SERIAL_CHUNKS=8`), `src/consensus_net.rs:531-538` (`send_timeout` default 2000ms, `STELL_SEND_TIMEOUT_MS` ≥500; WAN 11s peer needed raise — votes never landed), `560-575` (join 500ms), `581-594` (probe evict 3); `src/consensus_net.rs:3861` (`COMMITTED_INNER_BUDGET_PER_TICK=8`), bulk limiter + `inbound_is_critical` (only `Committed` bypasses).

**Live incidents quoted in code:** 2026-10-13 observer (1vCPU, ~1800 behind): `request_to` 2500-3500ms while B→C 269ms + `too many concurrent streams (256)` + `sending stopped by peer` — fan-out was 128 probes × (state+7 domains+header+QC) × manifest/chunks + replicate pushes + instant retries → dropped streams → timeout → re-flood. Fix = 8-wide fetch sem + 2-wide snapshot lane (nest fetch-then-snapshot, no deadlock) + jittered backoff (spread synchronized re-flood) + serial chunk resume (50-chunk blob at 5% drop fails 92% without per-chunk resume) + probe pacing.

## 10. Pruning KEEP bounds vs walk depth

| Horizon | Default | Knob | What is kept | Sync consequence |
|---|---|---|---|---|
| Local sled bodies | 50_000 (archive default; prune opt-in) | `STELL_ARCHIVE=0` + `STELL_KEEP_BLOCKS=<n>` (`src/storage.rs:248-263`, `src/main.rs:3752`) | bodies ≥ tip−KEEP; headers/receipts retained (`prune_blocks_below`, `src/storage.rs:858`; `body_is_removable: h+1 < keep_from`) | below-window bodies only on DHT retro window |
| DHT bodies/headers/QC/index | 8000 | `STELL_KEEP_BLOCKS` → `retention_keep_blocks` (`src/network.rs:244-251`), fallback `STELL_DHT_KEEP_BLOCKS_DEFAULT` | `H < tip−KEEP` deleted by publisher (`prune_below_exclusive`, `prune_batch`, `plan_retained_prune`); TTL `keep*120s` clamped [7d,30d] collects replicas (`dht_blob_ttl_ms`, `src/network.rs:270-278`) | full header-anchored catch-up bounded to ≤KEEP behind; QC sidecar retention == header retention (pruned QC = "skip boundary", `src/network.rs:377-384`) |
| Snapshots + head | forever | `STELL_DHT_FOREVER_TTL_MS` (100y) | every-100 state + domains + head pointer, never pruned (`src/network.rs:167-170,365-391`) | far-behind anchor always exists |
| Retro serve window | 4096 / 128 per pass | `RETRO_PUBLISH_DEPTH/MAX_PER_PASS` (`src/main.rs:35-38`) | last 4096 bodies republished, cursor-drained | KEEP (8000) ≫ 4096 + remainder ⇒ every body sync asks for is retained (`src/network.rs:155-161`) |
| Body walk | 256 heights | hard cap in `walk_chain` (`src/main.rs:2250`, `collect…256`) | — | `gap>256` MUST snapshot; `ADOPT_REPL_RETRO_DEPTH=4096` / `KEEP_WINDOW=8000` (`src/sync.rs:1151-1155`) gate the adopter backfill the same way |

State-snapshot local retention: keep last few for reorgs (`prune_state_below` keeps max, `src/storage.rs:941-963`); domain/snapshot cadences documented `src/storage.rs:1488-1602`.

---

## Ranked improvement list (faster / safer sync + risks)

1. **Close N3 stale-set refusal (biggest strander).** Before refusing tail anchor on QC-verify failure, pull CURRENT set via `refresh_validator_set_from_fresh_snapshot` (set-only, bounded, fail-closed) and retry once (`src/sync.rs:497-507`). *Gain:* unstrands drifted nodes without wipe. *Risk:* extra domain fetch per refusal; must keep fail-closed (attacker set never installs — freshness-gated).
2. **Close N4 stale-set trap in `try_catch_up`.** When peer ahead AND both walk + snapshot fail in one round, run set-only refresh once and retry walk (`src/main.rs:2164-2175`). *Gain:* fixes wrong-CONFIG-set nodes that never set stale flag. *Risk:* one more DHT round per failed tick; bound it (once per round, not per boundary).
3. **Bounded header availability signal (N5 publication gap).** Track consecutive "header present, QC missing" vs "both missing" (lane-split artifact already fixed in `persist_block_header`, `src/network.rs:803+`) and surface which boundary class fails. *Gain:* distinguishes pruned vs unpublished vs split-brain quickly. *Risk:* logging only — no consensus change.
4. **Snapshot-pointer-first everywhere + wider tail probe budget.** `try_snapshot_sync` already prefers `fetch_latest_snapshot`; extend same pointer check to the set-only refresh candidate list ordering and raise `PROBE_STEPS=8` only when pointer present (worker-timed heights). *Gain:* fewer 800-height guaranteed-miss walks. *Risk:* pointer is fail-closed (bounds-checked `latest<=peer`), so trust is minimal; extra fetch is one tiny blob.
5. **Adaptive `walk_chain` chunking under the 256 cap (do NOT raise cap).** Keep 256 hard bound (DoS load-bearing, N6) but pipeline bodies in `ADOPT_REPL_MAX_CONCURRENCY=8` batches with per-height 5s timeout instead of strictly serial `fetch_block` when gap is 100–256. *Gain:* 40-block WAN gap heals in ~1 pass not ~8s+timeout. *Risk:* concurrency must stay under `FETCH_MAX_CONCURRENCY=8` + yield per height or consensus starves (existing `yield_now` discipline).
6. **Catch-up budget auto-tune by gap class.** Today's three static tiers (5s/30s/180s + 250ms outer) drop mid-flight snapshot assembly on jitter. Keep outer 250ms for near-tip, but exempt in-flight `SNAPSHOT_BLOB` assembly from outer timeout once manifest resolved (inner `snapshot_blob_budget_ms` already bounds it). *Gain:* fewer zero-progress snapshot retries. *Risk:* long tick blocks rounds — acceptable only while far behind (node validates nothing anyway), must retain near-tip tight budget.
7. **Deduplicate snapshot/domain fetches across overlapping subtasks.** Probe loop, tail anchor (3 heights × 3 blobs), and domain bundle re-fetch same blobs; add short-TTL in-memory blob cache keyed by (epoch,bucket,name). *Gain:* cuts 2026-10-13 fan-out at source. *Risk:* memory bound needed; must never serve across epoch change.
