# Integration Review — node / runtime / storage / API / contracts / infnode

**Reviewer:** subagent (read-only pass)
**Date:** 2026-11-18
**Mode:** read-only. No source or test file was modified. This document is the only file written.

---

## Verdict

**FAIL for mainnet. PASS WITH CONDITIONS for public testnet.**

No defect found in the reviewed paths lets a *fork be finalized silently*, lets an unauthenticated peer *mint consensus power*, or lets a *corrupt snapshot become quorum state*. The consensus and sync trust chain is unusually well defended and consistently fail-closed.

Mainnet is blocked by one **economic-invariant defect** in the staking payout path (value-moving legs use the *mint* primitive, so the lifetime emission cap is charged twice per reward and once per withdrawal), plus a set of durability and honesty gaps that are tolerable on testnet but not on a value-bearing chain. Details and exact fixes below.

---

## Scope and method

Reviewed (targeted reads/greps, no full test run):

| Area | Files | Notes |
|---|---|---|
| Node | `node/bootstrap.rs`, `consensus_driver.rs`, `policy.rs`, `sync.rs`, `upgrade_halt.rs` | startup, recovery, halt, heal-to-head, gossip ingress |
| Runtime | `runtime/mod.rs`, `anchors.rs`, `apply.rs`, `consensus_step.rs`, `lanes.rs`, `mev_sync.rs`, `cluster.rs` | sequencing, finality, staking legs, xshard, lane worker |
| Storage/sync | `storage.rs` (5 474 L), `sync.rs` (3 472 L) | versioned wrappers, paired restore, trust anchors |
| API | `rpc/*`, `explorer.rs`, `client_ip.rs` | auth, caps, honesty, DoS |
| Contracts/EVM | `contract.rs`, `contract_abi.rs`, `evm_adapter/*` | host imports, fuel, ABI, selectors, `eth_*` |
| Transport | `infnode/src/{proto,node,config,keyring,mailbox}.rs` | frame auth, TOFU, KEM, ACL, blob caps |

Note: the requested `infnode/.../dns_seeds.rs` does not exist; DNS seed discovery lives at `stellereum/src/dns_seeds.rs` and is reviewed there.

Not reviewed in depth (recorded as out of scope / UNVERIFIED): `state_engine/**` internals, `svm.rs`, `sharding/**`, `mev_epoch.rs`, `bridge.rs`, `tokenomics.rs`, `governance.rs` beyond the upgrade-plan commit path, and the `rpc/tests.rs` suite (317 k L).

---

## Findings

Severity: **Critical** = chain split / theft / total loss; **High** = must fix before mainnet; **Medium** = fix or explicitly accept before mainnet; **Low** = hygiene / operational; **Info** = observation.

| # | Location | Severity | Blocks mainnet? | Summary |
|---|---|---|---|---|
| F1 | `runtime/anchors.rs:2181`, `:2320`, `:2355`, `:2422`, `:2473` | **High** | **yes** | Staking/reward payouts `debit_native(pool)` then `credit_native(payee)`; `credit_native` is the *mint* primitive and charges `TOTAL_SUPPLY_CAP`. Rewards are counted twice, withdrawals consume cap, and an honest claim can fail closed at the cap. |
| F2 | `storage.rs:3455-3458` (queue policy `:3211`) | **Medium** | conditional | When the persist queue is full (or on a current-thread runtime) *all* non-prune jobs are dropped, including `Consensus` (BFT checkpoint) and `Finalized` (tip pointer). |
| F3 | `evm_adapter/adapter.rs:695-706` + `:712-784` | **Medium** | no | `eth_call` ignores the `to` address and answers the node's global token metadata for *any* address/selector. A wrong-address query gets a plausible, fabricated `name()`/`balanceOf()`. |
| F4 | `node/sync.rs:78-95` + `policy.rs:246-251` | **Medium** | no | Snapshot probe falls back to 8 × 100-height steps, but the default snapshot interval is 1000 and the prune window is `3 × interval`. The fallback can miss every snapshot for a far-behind node; the comment at `node/sync.rs:79` ("~300 heights") is stale. |
| F5 | `infnode/node.rs:5340-5349` | **Low-Med** | no | `handle_storage_delete` does not call `role_allows(bucket)`, unlike `handle_storage_store:5096`. Any peer with an `allow` entry can delete chunks in buckets this node does not serve. |
| F6 | `storage.rs:1473-1487` | **Low** | no | A snapshot at the *finalized tip* with no successor header is accepted **without** root verification ("nothing newer to disagree with"). Cannot fork the network (peers reject), but a corrupt tip snapshot boots "healthy". |
| F7 | `storage.rs:2714-2791` | **Low** | no | Lenient `decode_domain_snapshot` fallback chain is heuristic bincode-prefix matching; `bincode::deserialize` allows trailing bytes. Reordered fallback (V8 before legacy-contract V4/V5/V6) contradicts the stated rule. Root verification is the real guard (see F6 for the tip exception). |
| F8 | `rpc/cache.rs:115-117` | **Low** | no | `.expect("finalized-read cache lock")` on a `std::sync::Mutex`: one panic while holding it poisons the cache and every later finalized-read RPC panics (persistent 5xx, not process death). |
| F9 | `contract.rs:8-9` | **Low** | no | Module docs claim "no host imports are linked … pure (i64)->i64", but `host_linker` registers `caller`, `value`, `block_time`, `block_hash`, `calldata`, `emit`, `sha256`, `blake3`, `falcon_verify` (`:1241-1294`). The imports are pure/sandboxed — the doc is what is wrong. |
| F10 | `rpc/contracts.rs:1113-1125`, `:206-217` | **Low** | no | The unsigned `stell_callContract` preview accepts a caller-supplied `caller` (never falls back to zero — good) and executes `block_hash = [0u8;32]`, so a contract that reads `block_hash` previews differently from live execution. Documented in code, not in the response. |
| F11 | `runtime/cluster.rs:504-508` | **Low** | no | `restore_checkpoint` swallows the restore error (`let _ =`), then `reorg` re-applies on whatever state is present. `ClusterRuntime` is used only from `runtime/tests`, so this is test/sim-only. |
| F12 | `node/consensus_driver.rs:1647`, `:3412-3413`; `bootstrap.rs:932` | **Low** | no | Swallowed `Result`s: mempool admission for gossiped txs (no metric), prune failures (silent disk growth), genesis-fingerprint write (a failed write is only re-attempted next boot). |
| F13 | `infnode/keyring.rs:315` | **Low** | no | `panic!` after `MAX_ATTEMPTS` of Falcon keygen. Startup-only and self-terminating, but a panic path on a consensus-node boot. |
| F14 | `runtime/anchors.rs:2443-2495` | **Low** | no | `stake_claim_delegator_rewards` returns `0` on a failed native leg instead of an error, so the caller cannot distinguish "nothing to claim" from "claim failed". |
| F15 | `runtime/mev_sync.rs:298`, `:820` | **Info** | no | Dead `let _ = state_root;` / `let _ = timestamp;` where a staleness check was intended; comments explain why it is unused. |
| F16 | `infnode/node.rs` `handle_node_svc` + `storage.store` | **Info** | no | Any ACL-allowed peer can `storage.store` arbitrary *unknown* chunk ids (hash checked only against a known manifest), 2 MiB each, with no total-disk quota. Bounded by per-peer rate (TOFU default 20/s) and `storage_roles`, but a trusted peer can still fill the disk. |
| F17 | `rpc/writes.rs:211-240` | **Info** | no | `stell_sendSealedTransaction` is unauthenticated by design (ciphertext only). Capped at `max_size/4` sealed slots; acceptable, worth a metric. |
| F18 | `upgrade_halt.rs:401-432` (guard) vs `consensus_driver.rs:2895` (trigger) | **Medium** | **yes** (as an invariant) | The halt marker gates only the *late* direction. A new binary started **before** `plan.height` sees no marker and boots immediately; if its `apply()` differs, the split surfaces as stalled finalization + `DIVERGENCE` rather than being prevented. |

### Upgrade machinery (no finding — recorded for completeness)

* The plan is committed (`governance.rs:1946-1961`, `commitment.rs:784`) and is part of the state digest, so a node that cannot represent `upgrade_plan` fails to decode/agree rather than forking.
* Execution is a deterministic sweep (`governance.rs:1817-1877`, ascending proposal id, re-derived tally, future-height check).
* The halt is a **predicate** (`consensus_driver.rs:2895`, `plan.height <= height`), drained (`:2928-2946`), then written as an atomic marker (`:2971`) **before** the optional `execve`.
* The startup guard runs before consensus and before RPC (`bootstrap.rs:960-993`, RPC spawn at `:1334`) and after persistence is up (`:939`).
* **Residual gap, now recorded as F18:** the marker enforces the *late* direction only (see the table). A new binary started **before** `plan.height` has no marker to trip and boots immediately; if its `apply()` differs, the divergence surfaces as a stalled finalization + `DIVERGENCE` log (`consensus_step.rs:472-494`) rather than being prevented. Coordinated upgrades therefore rely on the operator *not* installing early. Consider a "plan not yet reached but running version claims target" refusal in `guard_upgrade_halt`.

---

## Per-finding detail

### F1 — Staking payouts use the mint primitive (High, blocks mainnet)

`credit_native` is not a transfer; it is `mint_native`, which reserves against the global cap:

```rust
// state_engine/accounts.rs:1957
pub async fn credit_native(&self, addr: &[u8; 32], amount: u64) -> Result<(), String> {
    self.mint_native(addr, amount).await
}
```

and `debit_native` explicitly does **not** restore headroom:

```rust
// state_engine/accounts.rs:2041
/// A burn does NOT restore headroom: [`Self::total_minted_nano`] is gross
/// lifetime minting, so a burn-then-mint cycle can never create more than
/// the cap over the life of the chain.
```

The staking code pairs them, so every payout is a burn + a *new* mint:

```rust
// runtime/anchors.rs:2303-2320  (stake_withdraw)
self.state.debit_native(&crate::staking::STAKING_POOL, amount).await
...
if self.state.credit_native(&validator, amount).await.is_err() {
```

```rust
// runtime/anchors.rs:2408-2422  (stake_claim_rewards)
self.state.debit_native(&crate::staking::REWARDS_POOL, amount).await
...
if let Err(_e) = self.state.credit_native(&validator, amount).await {
```

Block rewards already reserve against the cap *once* when they fund the pool:

```rust
// state_engine/apply.rs:2638
self.state.credit_reserved_native(&crate::staking::REWARDS_POOL, block_reward)
```

Consequences:

1. **Reward claims charge the emission cap twice** (once minting into `REWARDS_POOL`, once paying it out). Effective emission headroom is roughly halved, and the cap is reached earlier than the tokenomics model states.
2. **Withdrawals** inflate `total_minted_nano` by the full principal returned. Stake churn permanently erodes headroom even though net supply is unchanged.
3. Once the cap is reached, an **honest claim/withdrawal fails closed** with a supply-cap error while the coins demonstrably exist in the pool. `stake_claim_delegator_rewards` then returns `0` silently (F14).
4. `anchors.rs:2181-2184` (`stake_bond`) credits the escrow with `credit_native` and ignores the error entirely. If that mint is refused, the ledger bond succeeds with no pool backing — the exact "mint" the M2 comment says it prevents.
5. The docstrings contradict the code: `stake_withdraw` says "withdrawals are paid OUT OF STAKING_POOL, never minted".

**Fix:** the payout leg must be `credit_native_transfer` (credits existing value, no cap charge), or a helper `transfer_from_pool` that debits and credits with a single supply-neutral primitive. Then make the escrow credit in `stake_bond`/`stake_delegate` propagate its error (refund the debit on failure). This is deterministic today (no fork), so it can be fixed at the next upgrade height — but it must be fixed before real value is at stake.

### F2 — Persist queue may drop consensus-relevant jobs (Medium)

```rust
// storage.rs:3455-3458
if !ok {
    eprintln!("[storage] persist queue full for {PERSIST_BLOCKING_WAIT_MS}ms; dropping a consensus-relevant job (disk too slow? — counted, alert on stell_persist_queue_dropped_total)");
    crate::metrics::global().inc_persist_queue_dropped();
}
```

All classes except `Prune` are `BoundedWait` (`:3211-3216`) and can therefore still be dropped after 200 ms. On a `CurrentThread` runtime the drop is **immediate** (`:3439-3446`), because the writer cannot drain while the producer blocks. `Consensus` carries the per-height BFT checkpoint and `Finalized` the tip pointer.

Mitigations that keep this from being High: finality (not the checkpoint) is the real double-vote guard; the checkpoint is only restored when its height matches (`consensus_driver.rs:643-645`, otherwise ignored); a lost `Finalized` is documented as "safe but slow". Node's default `#[tokio::main]` is multi-threaded.

**Fix:** never drop `Consensus`/`Finalized` — block (bounded) or fail the process loudly instead; at minimum, assert the production runtime flavour at startup and refuse to boot on `CurrentThread` when persistence is armed.

### F3 — `eth_call` answers for any address (Medium; FIXED)

`eth_call` now reads `params["to"]` and delegates to
`eth_call_target_code_status`, which uses the same committed lookup as
`eth_getCode`. A target with no committed code returns `"0x"`; a
target-less call keeps the legacy native-token view. State-changing selectors
(`transfer`/`approve`/`transferFrom`) and `allowance` also return `"0x"`, never
a fabricated success (`evm_adapter/adapter.rs:673-810`).

Residual (unchanged): the price is still a native-token adapter, not an EVM
interpreter — a metadataless call object can still get the documented
native-token constants. That is an intentional emulation, not a per-address
fabrication.

### F4 — Snapshot probe window vs. snapshot interval (Medium)

```rust
// node/sync.rs:78-95
// only ~300 heights of snapshots (see prune_state_below(height - 300)),
// so probing past 8 boundaries (800 heights) is guaranteed to miss ...
const PROBE_STEPS: u64 = 8;
let mut boundary = (peer_height / 100) * 100;
if let Some(latest) = adapter.fetch_latest_snapshot(shard).await { ... boundary = latest; }
```

```rust
// node/policy.rs:246-251
pub fn snapshot_interval() -> u64 {
    std::env::var("STELL_SNAPSHOT_INTERVAL").ok().and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1000).max(50)
}
```

Pruning keeps `snap_int * 3` (`consensus_driver.rs:3409`), not 300. The probe step is hard-coded to 100. With the default interval 1000 and a peer at, e.g., height 4999, the 8-step walk probes 4900…4200 and never reaches the snapshot at 4000. Recovery then depends entirely on `fetch_latest_snapshot` (which is well built: the pointer advances only after the state blob lands, `network.rs:1163-1199`). If that pointer is ever unreadable (TTL/GC, epoch rollover, partial publish), a node more than `max_walk_gap` (`= interval + 64`, ≤ 4096) behind strands at its old height, and the body walk is explicitly skipped (`node/sync.rs:695-698`).

**Fix:** derive the probe step from `snapshot_interval()` (or probe `latest, latest-interval, …`), and update the stale comment. Optionally treat "pointer miss + no snapshot in window" as a loud, distinct status for the watchdog.

### F5 — `storage.delete` skips the bucket-role gate (Low-Med)

```rust
// infnode/node.rs:5340-5350
async fn handle_storage_delete(self: &Arc<Self>, v: &serde_json::Value) -> Option<Vec<u8>> {
    let id = v["chunk_id"].as_str().unwrap_or("").to_string();
    if !self.valid_chunk_id(&id) { ... }
    let bucket = v["bucket"].as_str().unwrap_or("files");
    let path = self.chunks_dir(bucket).join(&id);
```

Compare `handle_storage_store`:

```rust
// infnode/node.rs:5096
if !self.role_allows(bucket) {
    return Some(json!({ "ok": false, "err": format!("bucket '{bucket}' is not in this node's role") })...);
}
```

Path traversal is closed (`chunks_dir` filters to alphanumeric), and the ACL does gate node services (`node.rs:7764` precedes `handle_node_svc` at `:7773`), so only ACL-allowed peers reach this. Still, a trusted peer can delete chunks from a bucket this node is not a storage holder for. Add the same `role_allows` check.

### F6 — Tip snapshot accepted without verification (Low)

```rust
// storage.rs:1473-1487
let Some(expected) = self.expected_restore_root(snapshot_height)? else {
    let tip = self.finalized()?.map(|(h, _)| h).unwrap_or(snapshot_height);
    if snapshot_height < tip {
        return Err(anyhow!("no anchor to verify snapshot at height {snapshot_height} ..."));
    }
    return Ok(());
};
```

This is deliberate and documented. The blast radius is local: the node may resume on state nothing vouches for, but its next proposal carries a wrong root and the network refuses it. Worth an operator-facing warning line rather than silence.

### F7 — Heuristic snapshot decoding (Low)

```rust
// storage.rs:2714-2731
pub fn decode_domain_snapshot(bytes: &[u8]) -> Result<DomainSnapshot> {
    if let Ok(snap) = bincode::deserialize::<DomainSnapshot>(bytes) { return Ok(snap); }
    if let Ok(v8) = bincode::deserialize::<DomainSnapshotV8>(bytes) { ... return Ok(v8.upgrade()); }
    if let Ok(v4) = bincode::deserialize::<DomainSnapshotV4>(bytes) { ... }
```

Two residual hazards, both mitigated but not eliminated:

* `bincode::deserialize` allows trailing bytes, so a *future* shape with appended fields would decode as the current one and silently drop them (only relevant to rollback, which is unsupported).
* The fallback order tries `V8` (current contracts + `StakingLedgerV5`) **before** the legacy-contract shapes `V4/V5/V6`, although the comment above the block states legacy contracts are tried first. Prefix-compatible shapes can in principle misparse into a *wrong* struct rather than an error. On the local-restore path the throwaway-engine root check catches it (except F6); on the trust path `decode_domain_snapshot_strict` (`:2815`) rejects anything but the current shape with `reject_trailing_bytes`. That strict/lenient split is the right design — keep it, and reorder the fallbacks to match the comment.

### F8 — Poisoned cache lock panics every finalized read (Low)

```rust
// rpc/cache.rs:115-117
let mut cache = finalized_read_cache()
    .lock()
    .expect("finalized-read cache lock");
```

No `panic = "abort"` profile is configured, so this unwinds per request; the server survives but the cache is permanently poisoned and every subsequent hit panics. Use `unwrap_or_else(|e| e.into_inner())` (the cache is safe to reuse after a panic) or a poison-free lock.

### F9 — Contract module doc contradicts the host imports (Low)

```rust
// contract.rs:8-9
//!   - no host imports are linked, so a contract cannot reach the network, the
//!     clock, or host memory — it is a pure (i64) -> i64 function;
```

The host module exists and is charged for: `caller`, `value`, `block_time`, `block_hash`, `calldata`, `emit`, `sha256`, `blake3`, `falcon_verify` (`:1241-1294`). All are pure and fuel-charged, `caller` is copied into guest memory through the bounds-checked `write_wasm_memory` (`:1247`), and `emit` enforces `MAX_CONTRACT_EVENTS` (`:1229`). Only the documentation is stale — and in a security review, a doc that says "no imports" next to an import table is worse than no doc.

### F13/F15/F12 — Panic and swallowed-`Result` inventory

* `infnode/keyring.rs:315`: `panic!("PqKeys::generate failed ...")` after retries. Acceptable as a last resort, but prefer returning `Err` to `main` for a clean systemd failure.
* `runtime/mev_sync.rs:298`, `:820`: `let _ = state_root;` / `let _ = timestamp;` — remnants of a dropped staleness check.
* `node/consensus_driver.rs:1647`: `let _ = pool.add_checked_ctx(tx, bal, octx);` — a gossiped tx can be silently rejected with no counter. Add `inc_mempool_refused(reason)`.
* `node/consensus_driver.rs:3412-3413`: prune failures are `let _ =` inside a background task.
* `bootstrap.rs:932`: `let _ = storage.set_meta("genesis_state_root", &genesis_root);` — a failed fingerprint write is invisible; the next boot recomputes and may accept a different genesis if the store write keeps failing.
* `contract.rs:1241-1294`: `let _ = linker.func_wrap(...)` for every host import; a registration failure would surface only as a guest `HostFuncNotFound`.

None of these is on a path that can *mint* or *finalize* wrongly; they are operability/hygiene.

---

## Reviewed and found clean (with evidence)

### Startup and recovery

* **Fresh genesis is deterministic and guarded.** Validator set built before funding (`bootstrap.rs:697-714`), genesis fingerprint recorded and compared with a loud refusal on mismatch (`:912-937`), legacy v1 root special-cased. A fresh join with peers/DNS configured is refused unless the operator opts into observer join (`:662-695`).
* **No boot on unverified state.** `load_full_state_into` refuses unpaired snapshots (`storage.rs:2956-2968`), restores into a throwaway engine, verifies the root against the header at `H+1` (`:2992-3068`), and only then touches the live engine. Any failure exits 1 with an actionable message (`consensus_driver.rs:461-467`).
* **Heal-to-head is mandatory and bounded.** Engine behind head ⇒ heal from peers, 3 attempts, then `process::exit(1)` (`:568-638`, `policy.rs:914-926`); a stale snapshot is *never* relabelled as the tip (`:536-563`). Stale validator ledger ⇒ observer mode, votes disabled (`consensus_step.rs:1401-1406`, gate at `consensus_driver.rs:1670-1681`).
* **Corrupt blob ⇒ fail closed.** Anchor hydration leaves the registry empty and says so loudly (`bootstrap.rs:39-70`); `latest_paired_snapshot` mismatch refuses (`storage.rs:2962-2966`).

### Upgrade machinery

* Plan committed in `AppliedParams`, part of the digest (`commitment.rs:784-788`), executor deterministic, idempotent, chain-bound, future-height enforced (`governance.rs:1817-1972`).
* Halt is a predicate, drained with a 240 s cap, marker written atomically (temp + fsync + rename + fsync dir) *before* exec (`upgrade_halt.rs:220-234`, `consensus_driver.rs:2919-2993`).
* `execve` is **opt-in** (`STELL_AUTO_UPGRADE`, default off, `governance.rs:772-788`); candidate names are single safe segments; verified bytes are staged into a private dir and *that* copy is executed; symlinked candidate and symlinked parent refused; size-capped (`governance.rs:701-723`, `:833-860`).
* Frame version negotiation fails closed on disjoint ranges (`infnode/proto.rs:154-161`); `COMMITMENT_VERSION` is inside the digest (`commitment.rs:1710`), so a version skew produces a root mismatch, not a silent fork.

### Storage compatibility

* Every legacy wrapper is read-only (`DomainSnapshotV1..V8`, `StakingLedgerV4/V5`, `ContractLegacy`, `GovernanceLegacy`); each documents *why* the migrated value is exact. Some carry `#[serde(default)]`, but the module correctly states (`storage.rs:2525-2527`) that bincode cannot honour it — nothing relies on it.
* `decode_domain_snapshot_strict` is used for every trust-anchor path (`sync.rs:1376-1381`, `storage.rs:2841-2848`) with `reject_trailing_bytes` + a 512 MiB cap; the lenient decoder is confined to local restore. This is exactly the right split.
* Versioning discipline is mostly "append a field *and* add a read-only wrapper" (`oracle`, `recent_full_exits`, jail/commission/lock, balance/ABI). The one in-place append to the frozen `DomainSnapshot` (the `oracle` field, `storage.rs:2121-2127`) is explicitly documented as a wipe boundary tied to the `COMMITMENT_VERSION` bump — acceptable, but it is the exception rather than the rule, and F7 is the residual risk in the fallback chain.

### Network / identity (infnode)

* **PQ-only frame auth.** `Frame::verify` requires a `PQ_FALCON_SIG_LEN` tag and Falcon verification over `blake3(sign_data)` (`proto.rs:337-345`); there is no classical branch (`FRAME_VERSION == 2`, v1 refused, `:135-145`).
* **CHALLENGE → AUTH with KEM.** `pq_responder_accept` binds the transcript; session key is `blake3(PQ_SESSION_DOMAIN || shared || digest)` (`proto.rs:103-116`); a CHALLENGE without PQ fields is refused with no fallback (`node.rs:7448-7461`). Session table and digest table are capacity-bounded and fail closed (`:7462-7476`).
* **TOFU is sound.** Unknown peers must sign the challenge, the claimed id must equal `pq_id_from_pub(pk)` (`node.rs:7375-7380`), and a re-used id with a different key is refused with a MITM warning (`:7381-7393`). Dynamic peers are born rate-limited (20/s), never unlimited (`:7401-7403`). Default `allow-unknown: false`; TOFU default ACL is read-only discovery (`config.rs:12-21`).
* **Replay/dedupe bounds.** Per-connection replay windows (documented deliberate trade-off: duplicates accepted as a max-gate to avoid outages, `node.rs:7558-7575`), nonce claim prunes by `TS_WINDOW_MS` and refuses at `MAX_SEEN_IDS` rather than evicting (`proto.rs:53-69`), pre-auth deadline 15 s, per-IP handshake token bucket.
* **Blob caps.** `MAX_FRAME` 32 MiB, `MAX_STORAGE_CHUNK_LEN` 2 MiB, assembled blob capped at 32 MiB with chunk-count and per-chunk hash checks (`node.rs:6099-6188`), `MAX_DHT_VALUE_LEN` 1 MiB, TTL clamped, `recovery:`/`blacklist:`/`share:` keys refused from the network (`:4453-4462`).
* **DNS seeds.** Record must start `stellereum/v1`, `node_id` must derive from the embedded Falcon key, legacy `ed=`/`x=` refused, full KEM key verified against the `kem_hash` pin before use, 32-peer cap, 4 KiB record cap (`dns_seeds.rs:9-100`, `:156-159`). Discovery peers never enter `cfg.validators`.
* **Key material.** Key dir 0700, key files 0600, insecure perms refused at load (`keyring.rs:139-156`, `:410-422`).

### Sync (node + crate)

* Trust chain is: header at `B+1` → its `state_root` → restore must reproduce that root → set-at-height binding (strict decode, non-empty, equal to the anchor set) → replay-coverage gate → only then install (`sync.rs:1222-1345`). Every gate precedes mutation.
* Chain-anchored walk proves per-height QCs from *our* finalized head; genesis-anchored uses a bounded trailing window with per-height QCs — no "hash-linked but forged" acceptance (`node/sync.rs:160-251`).
* A peer's `prev_hash` is never trusted for the head/sortition parent; the boundary hash comes from the verified anchor (`node/sync.rs:293-328`).
* Missing `cross_shard` blob with non-empty local replay state is refused (double-mint protection), and a non-covering set is refused (`sync.rs:1291-1335`).

### Runtime / finality

* Finality refuses a block it does not hold, a body whose hash no longer matches, an order-commitment mismatch, an over-cap actor block, and a QC below quorum under the set in force *at that height* (`apply.rs:555-700`). Missing precommit QC ⇒ refuse (no unilateral finalization).
* Post-state divergence is detected and paged with a `DIVERGENCE` tag rather than auto-resolved (`consensus_step.rs:472-494`).
* The apply worker is single-task, FIFO, panic-guarded (`catch_unwind`), parks the height on panic rather than advancing (`lanes.rs:290-327`); snapshots are root-gated and skip loudly rather than mislabel (`:328-345`).
* Stale/foreign validator sets cannot vote (`consensus_step.rs:1401-1406`); xshard message verification is fail-closed on unknown kinds, missing registry, root mismatch, and reversed direction (`anchors.rs:1433`, `:1537`, `:1555`, `:1598`, `:1626`, `:1698`).

### RPC / API / explorer

* Bounds: 1 MiB body (`state.rs:12`, `DefaultBodyLimit` at `streams.rs:1658`), same-size batch limit, 512 concurrent, request timeout, per-IP fixed-window limiter plus a dedicated nested-RPC limiter (`explorer.rs:337-362`).
* Subscription DoS: global 4096, per-client 64, 1 h TTL sweep, WS idle reap (`streams.rs:17-45`, `:209`, `:985-1033`).
* Pagination caps: recent blocks 100, receipts 50 000, events `MAX_EVENTS_RETURNED`, logs 1000, proof keys 32, `limit` clamped (`state.rs:295,346`, `reads.rs:540,1828,2025`).
* Auth: governance writes, contract previews, mempool dump, signing arms are **fail-closed without a token on every bind** (`auth.rs:183-204`, `rpc/mod.rs:43-76`); sign arms additionally require dev mode + loopback (`mod.rs:68-73`). `sendRawTransaction` is open by design and self-authenticating (PQ envelope + signature + nonce/balance gates).
* Honesty: receipts resolve only from the single real application or the durable store, else `None` (`eth.rs:164-208`); logs are `[]` rather than invented (`:589-591`); `eth_feeHistory` is refused with an explanatory error (`:760-766`); uncles are `null`; `eth_syncing`/`net_peerCount` use live counters; `eth_getProof` verifies its own generated proof (`adapter.rs:2506-2527`); `eth_getStorageAt` returns zeros because no EVM trie exists.
* Preview semantics: executes on a **clone**, writes no receipt, never admits or gossips, tags the response `preview_only`/`mined:false`, and uses the transaction's real `from` when the `tx` form is used (`contracts.rs:230-352`).
* Faucet: fail-closed without `STELL_FAUCET_TOKEN`, POST-only, per-IP hourly budget, per-address lifetime cap, persistent state, corrupt record does not mint credit (`faucet.rs:59-67`, `:390-414`, `:561-626`; `explorer.rs:556-630`).
* `client_ip`: loopback-only trusted proxies by default, `rightmost` XFF by default, explicit spoofing analysis (`client_ip.rs:11-50`).

### Contracts / EVM

* No network/filesystem imports; the only host calls are pure or consensus-deterministic (`block_time` is the committed block timestamp, `block_hash` the committed value, `caller` the authenticated `tx.from`), each fuel-charged; memory/table/instance limits via `StoreLimits`; deploy-time validation and import resolution (`contract.rs:1-18`, `:436-490`, `:1241-1294`).
* Fuel: `fuel.min(MAX_CONTRACT_FUEL)` (50 M) per call, separate 1 M get-method budget, per-byte calldata charge (`contract.rs:784`, `:1286-1288`; `reads.rs:309-322`).
* `host.caller` is copied into guest memory with bounds checking (`:1244-1248`); no guest write path into the host context; `caller` for on-chain execution comes from the authenticated `tx.from`.
* ABI: `MAX_ABI_ARGS = 16`, `MAX_ABI_BLOB_LEN = 1 MiB`, unknown method / wrong arity rejected, truncated and trailing bytes rejected (`contract_abi.rs:62-64`, `:971-1010`, `:1116`, tests `:1607`).
* Selectors are correct keccak prefixes: `06fdde03`, `95d89b41`, `313ce567`, `70a08231`, `18160ddd`, `a9059cbb`, `23b872dd` (`evm_adapter/types.rs:136-156`).

---

## Ready for public testnet?

**Yes, with conditions.** No fork-inducing or authorization-bypass defect was found. Before opening the faucet/explorer to the public, fix or consciously accept:

1. F8 (poisoned cache lock ⇒ persistent 5xx) — one-line fix.
2. F5 (`storage.delete` role check) — one-line fix.
3. F3 (`eth_call` address check) — small fix; otherwise wallets will show wrong token metadata.
4. F4 (probe window) — monitor `[sync] snapshot-sync ... no usable snapshot` and keep `fetch_latest_snapshot` healthy; align the probe eventually.
5. Keep `allow-unknown: false` once peers are pinned; the TOFU fingerprint must be verified by the operator.

F1 is deterministic, so testnet will not fork on it; it will simply burn emission headroom and eventually make claims fail. Acceptable only while no real value is at stake.

## Ready for mainnet?

**No.** Exact blockers:

1. **F1** — staking/reward payouts must be supply-neutral (`credit_native_transfer`), the double charge of `TOTAL_SUPPLY_CAP` removed, and the escrow credit errors propagated. *Blocking.*
2. **F2** — guarantee `Consensus`/`Finalized` persist jobs are never dropped; assert the multi-thread runtime (or block until drained). *Blocking.*
3. **F4** — recovery must not depend on a single pointer blob; probe by `snapshot_interval()` and add a distinct watchdog state. *Blocking.*
4. **F3** — `eth_call` must not attribute metadata to arbitrary addresses. *Blocking for public RPC.*
5. **Upgrade "early start" gap** — decide explicitly whether a new binary may run before `plan.height`; if not, add a startup refusal (marker only covers the late direction). *Blocking as a documented, tested invariant.*
6. **F6/F7** — eliminate the unverified tip-restore path and reorder/normalise the legacy decoder (or gate it behind an explicit operator flag). *Blocking (defence in depth).*
7. Operability: F8, F12, F15, F17 resolved; `allow-unknown: false`; external audit of `state_engine`, `svm`, `sharding`, `mev_epoch`, `bridge` (out of this review's scope) still required.

---

## Unverified / limits of this review

* I did not run the test suite or the consensus liveness harness (explicitly disallowed). Statements about behaviour are from code reading, not execution.
* `state_engine/**` internals, `svm.rs`, `sharding/**`, `mev_epoch.rs`, `bridge.rs` were not audited; findings that depend on them are flagged as such.
* Whether every network-rule change is activation-height-gated (which determines the real impact of the "early start" upgrade gap) is **UNVERIFIED**.
* Whether production deployments ever run the persistence queue on a `CurrentThread` runtime is **UNVERIFIED**; the code handles it, but by dropping every job.
* The `eth_call`/`block_hash` preview divergence (F10) was confirmed from code but its practical impact on real contracts is **UNVERIFIED** (no deployed contract was inspected).
