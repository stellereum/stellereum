# Operators

Lifecycle: `install → configure → keygen → join → snapshot-sync →
monitor → alert → prune → upgrade → rollback → disaster-recover`.
Authority: `docs/OPERATIONS.md`; join scripts (from repo root): `./scripts/join-testnet.sh`,
`./stellereum/scripts/add-peer.sh`; health tooling: `./scripts/stell-sync.sh`,
`./scripts/doctor.sh`, `./scripts/cluster-watchdog.sh`,
`./scripts/node-prune-cron.sh`, `./scripts/tools/stelops/`.

## The pipeline

1. **Install:** `cargo build --bin stellereum`; place the binary
   **outside** any cargo target dir (incident 4 — `cargo clean` deleted a
   live binary → 203/EXEC crash-loop).
2. **Configure:** `node.yaml` (`peers:`, `validators:`, DNS seeds) + env
   file (mode 600). Values that must match **every** node: `STELL_SHARDS=0`
   (single-shard masterchain; shard 1 is parked), chain id (`5757`),
   `STELL_MIN_BLOCK_MS=400` (live fleet; code default 50),
   `STELL_KEEP_BLOCKS=50000` (code default in prune mode), admission
   base fee — drift = split or silent isolation (`OPERATIONS.md` §15.3). The
   base round timeout is **compiled** (`FROZEN_ROUND_TIMEOUT_BASE_MS = 3 000`);
   the former `STELL_ROUND_TIMEOUT_MS` env override is gone, so it must match
   by running the same binary/ruleset. `STELL_DOWN_PROPOSER_TIMEOUT_MS`
   (default 800) stays node-local policy.
3. **Keygen:** `stellereum keys init` (0700/0600, encrypted `enc2:` by
   default; passphrase via `STELL_NODE_PASSPHRASE`, never in history).
   Falcon pre-FIPS keys still load; migrate with
   `keys rotate-falcon --force` (changes the validator address → re-stake).
4. **Join:** from repo root, `./scripts/join-testnet.sh --mode observer|validator`
   (accepts `--home`, `--name`, `--listen`, `--advertise`, `--rpc`, `--explorer`,
   `--seeds`, `--peers-file`, `--snapshot-url`, `--sha256-url`, `--require-sha256`,
   `--refresh-store`, `--skip-snapshot`, `--binary`, `--chain-id`,
   `--commission-bps`, `--force`, `--start`, `--non-interactive`; writes
   `node.yaml` + `node.env` with `STELL_SHARDS=0`, `STELL_OBSERVER=1`, and
   downloads the snapshot — pass `--skip-snapshot` when `node-bootstrap` follows
   in step 5) → send `peer-stanza.txt` to the admin → admin
   `./stellereum/scripts/add-peer.sh` (observer: peers only; `--role validator`
   changes genesis = coordinated restart).
5. **Snapshot-sync:** `stellereum node-bootstrap` — fail-closed preflight
   (clean dir, `STELL_OBSERVER=1`, faucet key, peers, non-empty
   validators), then state + all domains with per-height QC proofs, then
   body walk, then live follow. Never join by copying another node's
   `./data`.
6. **Monitor:** `/readyz` (readiness + `failed_checks`), `/metrics`
   (alert on the **derivative** of `stell_consensus_height`), per-minute
   `stell_getStateRoot` agreement across nodes (the single most valuable
   check), `stell_getValidators` quorum watch.
7. **Alert:** `health_check.sh` (exit 0/1/2), `cluster-watchdog.sh`
   (auto-heals only safe cases: dead service, inode pressure).
8. **Prune:** archive is the default (unbounded growth; local `./data`
   measured 2.9 GB). Recommended prune starting point: `STELL_ARCHIVE=0`,
   `STELL_KEEP_BLOCKS=50000` (code default) — keep retention settings
   coherent across nodes.
9. **Upgrade:** governance `SoftwareUpgrade` stages + hashes before exec
   (`stage_verified_upgrade_binary`); live `execve` only with
   `STELL_AUTO_UPGRADE=1`, else exit 42 for the supervisor
   (`OPERATIONS.md` §12).
10. **Rollback:** restore from `stellereum/scripts/backup/` tarballs (whole `./data`,
    never single files); a genesis-era mismatch refuses loudly — that
    refusal is the safety net.
11. **Disaster-recover:** coordinated whole-`./data` wipe on **all** nodes
    at once for a new genesis; single-node wipes re-fork. Last resort.

- Snapshot cadence: `STELL_SNAPSHOT_INTERVAL` defaults to **1000** heights in
  code; the live config uses **500**. Verify:
  `rg -n "SNAPSHOT_INTERVAL" src docs/OPERATIONS.md`.

## Tool map

| Tool | What it does | When |
| --- | --- | --- |
| `stell-sync.sh preflight` | fail-closed deploy gate: topic, genesis, chain id, timeouts, fees, inodes, binary path, unit state | before **every** deploy; refuse on failure |
| `stell-sync.sh health` | cluster table: service, inodes, orphans, topic, lock, binary hash, exit codes | the 90 %-of-incidents first look |
| `stell-sync.sh doctor [node]` | single-node diagnosis (config drift, checkpoint, topic, key format) | a node misbehaves |
| `stell-sync.sh lockclear <node> [--force]` | plan (read-only) then stop→verify→clear→start a stale consensus lock | stale-lock stall |
| `stell-sync.sh topic <node>` | expected vs subscribed pubsub topic | suspected isolation |
| `node-prune-cron.sh` (+ systemd timer) | orphan-chunk + snapshot sweeper (grace 6 h, cap 200 k/run, refuses on stale `kv.json`) | timer on **every** node |
| `cluster-watchdog.sh` | interval watcher; restarts dead units, prunes inodes; reports (never heals) topic/lock/tip stalls | always running |
| `scripts/tools/stelops/` | reads store checkpoint + genesis root, clears lock (`checkpoint`, `genesis-root`, `clear-lock`) | node stopped (sled locks) |
| `stall_watchdog.sh` | per-host: restarts via `stell-node.sh` after 180 s of flat heights | single-host deployments |
| `health_check.sh` | read-only probe (heights, mempool, disk, refusing-patterns) | cron/alert probe |

## Failure-mode table (from the five real incidents, §15)

| Symptom | Diagnosis command | Fix |
| --- | --- | --- |
| full disk: node "up", RPC fine, silently out of consensus (463 589 orphan chunks, `df -i` 100 %) | `df -i ./data`; `health` (inode %, orphans) | `node-prune-cron.sh --dir <dir>`; install the timer everywhere; alert warn 80 % / crit 90 % |
| topic drift: validator isolated, zero log evidence (`STELL_SHARDS` regressed `0,1`→`0`) | `stell-sync.sh topic <node>`; `preflight` | fix env to match cluster, restart (config error — never auto-heal) |
| stale lock: up, right topic, never finalises (resumed round 56 vs peers' 0) | `doctor` (checkpoint); `stelops checkpoint <store>` stopped | `lockclear <node> --force` (refuses if lock not ahead) |
| binary-in-target-dir: `status=203/EXEC` crash-loop after `cargo clean` | `preflight` (binary path); `health` (crash-loop) | move binary out of target dir, repoint `ExecStart`, restart |
| fork: same height, different `stell_getStateRoot` | per-node `stell_getStateRoot` + `stell_blockNumber` | find the config divergence (`validators:`, faucet key, chain id); do **not** wipe blindly |
| quorum-jump stall: set change takes effect mid-round, unilateral finality refused (`stell_weak_qc_refused_total`, W10.5 race) | `stell_getValidators` quorum vs reachable power | protocol now stages sets at H+1 boundaries (`PROTOCOL.md` I7b); re-check agreement, restart laggards — TODO: reproduce via `tests/w10_5_activation_race.rs`. Verify: `cargo test --test w10_5_activation_race` |
| nil-storm stall: repeated view changes with nil/precommit quorums never converging (polka unlock rounds) | `[consensus] view change` every 3 s + `rejected proposal` lines | check proposer schedule + order-root/shard-head rejections; §14.1 checklist — TODO: confirm the exact "nil-storm" signature live. Verify: `rg -n "nil" src/consensus.rs` + peer `readyz` |
