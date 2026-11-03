# LOCAL_VALIDATION — ops tooling vs local devnet (docs/ops 8.5 → 9.0)

Date: 2026-11-03. Scope: `scripts/status_snapshot.sh` + `ops/alert_rules.yaml`
only (plus this file). Local devnet ONLY (127.0.0.1): P2P 19411-19413,
RPC 18646-18648, explorer 18081-18083. No live hosts touched: every URL below
is 127.0.0.1; no ssh, no 212.x/138.x/77.x anywhere (`grep -rE '212\.|138\.|77\.'
uses only loopback` — assert by inspection of the commands pasted here).

## 1. Cluster lifecycle (started AND torn down by this run)

```
$ ./scripts/local-cluster.sh up
[local-cluster] binary: /home/imm/stellereum-project/stellereum/target/debug/stellereum
[local-cluster] mode: single-shard (plain topics, no workchain)
[local-cluster] phase 1: keygen for 3 nodes...
  node1: inf1:9e33a4865485ae23dbf26c12128a5bf143bd614c
  node2: inf1:8400e99455d1d12fd1b1c7424f215652f6318d1b
  node3: inf1:9d4a1f9ed3aef443e354ef32a3ddebb4ee9f51ce
[local-cluster] OK: epoch b76feefadaf33c5a identical on all 3 nodes; 2 common FINALIZED height(s), max #3.
NODE    ALIVE   FINALS     HEIGHT   EPOCH              RPC_BLOCK    RPC
node1   yes(833250) 2          #3       b76feefadaf33c5a   3            127.0.0.1:18646
node2   yes(833266) 2          #3       b76feefadaf33c5a   3            127.0.0.1:18647
node3   yes(833290) 3          #3       b76feefadaf33c5a   3            127.0.0.1:18648
```

## 2. status_snapshot.sh vs cluster status (height / set / version)

Raw RPC shape (the bug trigger — dict, not list):

```
$ curl -s -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"stell_getValidators","params":[]}' \
    http://127.0.0.1:18646
{"jsonrpc":"2.0","id":1,"result":{"fragile":true,"fragile_reason":"fragile validator set: N=3 ...",...,
  "validators":[{...},{...},{...}]}}
```

BEFORE fix — `scripts/status_snapshot.sh` reported a null set on a healthy node:

```
$ RPC_URL=http://127.0.0.1:18646 EXPLORER_URL=http://127.0.0.1:18081 ./scripts/status_snapshot.sh
{
  "ok": true,
  "height": 8,
  "metrics_height": 8,
  "heights_agree": true,
  ...
  "validators": null,        <-- BUG (script expected a bare JSON list)
  "mempool": 0,
  "chain_id": 5757,
  ...
}
```

BUG #1 (script, fixed — minimal, python block only): `stell_getValidators`
returns `{"validators": [...], ...}`; the parser did
`len(validators) if isinstance(validators, list)` → always `None`.
Fix handles the dict form, keeps list form working:

```python
# before
n_validators = len(validators) if isinstance(validators, list) else None
# after
if isinstance(validators, dict):
    _vl = validators.get("validators")
    n_validators = len(_vl) if isinstance(_vl, list) else None
else:
    n_validators = len(validators) if isinstance(validators, list) else None
```

AFTER fix — all fields parse and agree with `local-cluster.sh status`:

```
$ RPC_URL=http://127.0.0.1:18646 EXPLORER_URL=http://127.0.0.1:18081 ./scripts/status_snapshot.sh
{
  "ok": true,
  "ts": 1793704710,
  "height": 15,
  "metrics_height": 15,
  "heights_agree": true,
  "syncing": false,
  "state_root": "7c682ee3116e983027e3f35e3f200287e5ec6d838d2a7a65377a0fac8f575883",
  "validators": 3,
  "mempool": 0,
  "chain_id": 5757,
  "node_id": "inf1:9e33a4865485ae23dbf26c12128a5bf143bd614c",
  "version": { "version": "0.1.0", "git_hash": "a4b2e398f", "height": 15,
               "node_id": "inf1:9e33a4865485ae23dbf26c12128a5bf143bd614c", ... }
}
$ ./scripts/local-cluster.sh status
node1   yes(833250) 13   #15   b76feefadaf33c5a   15   127.0.0.1:18646
node2   yes(833266) 13   #14   b76feefadaf33c5a   15   127.0.0.1:18647
node3   yes(833290) 15   #15   b76feefadaf33c5a   15   127.0.0.1:18648
```

Match table (node1): height 15 == RPC_BLOCK 15 == HEIGHT #15;
metrics_height 15 == height (heights_agree true); validators 3 == 3 cluster
members; version.height 15 == chain height; node_id == keygen/cluster id.
Same agreement on node2/node3 (height 8/8/8 pre-fix, all nodes; state_root
identical on all three). Gate: `bash -n scripts/status_snapshot.sh` → clean.

No node-RPC bugs found: eth_blockNumber, stell_syncing, stell_getStateRoot,
stell_mempoolSize, stell_chainId, stell_nodeId, /api/version, /metrics all
responded with well-formed values. Nothing to REPORT against the node.

## 3. Alert rules vs local /metrics (node1, 127.0.0.1:18081)

Name check method: every `stell_*` series in `ops/alert_rules.yaml` grepped
against quoted literals in `stellereum/src/metrics.rs` — **all 14 present,
zero wrong names, so no yaml fix was needed.**

| rule | metric EXISTS locally | fires locally? | why / note |
|---|---|---|---|
| FinalsStalled | yes (`stell_consensus_height`=15) | no (healthy) | chain finalizing; fires only on real stall |
| RoundExplosion | yes (`stell_consensus_round`=0) | no | would need round >10 stuck |
| NilRoundsStall | yes (`stell_nil_rounds_total`=2) | possible | 2 nil rounds seen at startup; needs 3-in-10m |
| NilBreakerFired | name yes, **no samples** (counter never incremented → not rendered) | no (no-data) | needs nil-storm fault injection |
| QCFailures | yes (`=0` sample) | no | needs weak-QC event |
| ForkSpike | yes (`=0`) | no | needs conflicting block |
| DivergenceSpike | yes (`=0`) | no | needs divergence refusal |
| ValidatorSetFragile | yes (`=1`) | **YES (fires)** | expected: N=3 unanimous quorum is fragile by design (RPC `fragile:true`) |
| MempoolSaturatedWarn/Crit | yes (`=0`) | no, cannot | needs >1600/>1900 txs vs 2048 cap; thresholds sane per `mempool.rs` MAX_GLOBAL_BUFFERED_TXS=2048; no local loadgen, no fake tuning |
| SlowValidationSpike | name yes, **no samples** | no (no-data) | needs slow-validation event |
| PersistQueueDrops | yes (`=0`) | no | needs disk pressure |
| DiskAbove80Pct / DiskGrowthFast | yes (`stell_data_dir_bytes`=157724) | no, cannot | 157 kB vs 85 993 459 320 budget (~5 orders of magnitude); per-volume placeholder, must be retuned per host; predict_linear needs 1h history |
| PeersLost | HELP/TYPE yes, **zero per-peer samples** | **YES (fires, false-positive at local scale)** | nodes peered+finalizing, but no `peer=` latency samples rendered, so `count(...)=0 <3`; series appear only after latency observations (stale-series caveat already in file) |

Metric-name verdict: 14/14 correct — `ops/alert_rules.yaml` untouched.
promtool/pyyaml unavailable in this env, so no `promtool check rules`;
substitute proof is the metrics.rs literal grep + live /metrics presence above.

## 4. Teardown + orphan proof

```
$ ./scripts/local-cluster.sh down
[local-cluster] node1 stopped (was pid 833250).
[local-cluster] node2 stopped (was pid 833266).
[local-cluster] node3 stopped (was pid 833290).
$ ps aux | grep -E 'stellereum.*(run|--config)' | grep -v grep || echo "NONE - zero node processes"
NONE - zero node processes
$ ls run/cluster/node*/node.pid
zsh:1: no matches found: run/cluster/node*/node.pid     # pid files removed by stop_node
$ ss -ltn | grep -E ':(1864[6-8]|1808[1-3]|1941[1-3])' || echo "ALL-FREE"
ALL-FREE
```

Zero orphans: no node processes, no pid files, all 9 local ports free.
(Note: a broad `grep stellereum` also matches unrelated `rustc`/`cc1` build
workers from a concurrent cargo build in another session — none are node
processes started by this run, and none listen on the cluster ports above.)

## 5. Gates

- `bash -n scripts/status_snapshot.sh` → clean (before AND after fix).
- Validation doc complete (this file): commands + pasted outputs, bug
  before/after, per-rule fireability, teardown proof.
- Zero orphans: pasted above. Live hosts untouched: only 127.0.0.1 used.
