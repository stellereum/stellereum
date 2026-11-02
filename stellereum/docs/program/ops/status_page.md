# Operator status page spec

Minimal public status surface for a Stellereum node/cluster. Everything
published here is already public (RPC + `/metrics` + `/api/version` expose no
secrets — see the exposure enumeration in `stellereum/src/metrics.rs`).

## What to publish (and where each field comes from)

| Field | Meaning | Source (all verified to exist) |
|---|---|---|
| `height` | finalized head height (hex → int) | RPC `eth_blockNumber` (also `stell_blockNumber`); cross-check `stell_consensus_height` in `GET /metrics` |
| `finals_rate_10m` | blocks finalized per minute over 10m | computed from successive snapshots: `(h2-h1)/(t2-t1)`; raw inputs are `height` + `ts` |
| `state_root` | state root the head commits to | RPC `stell_getStateRoot` |
| `validators` | count + total power in the active set | RPC `stell_getValidators` (mirrors `stell_validator_set_size` / `stell_validator_power_total`) |
| `syncing` | whether the node is catching up | RPC `stell_syncing` |
| `mempool` | pending tx count | RPC `stell_mempoolSize` (mirrors `stell_mempool_size`) |
| `chain_id` | network identity | RPC `stell_chainId` (also `eth_chainId`) |
| `version` | binary version, git hash, dirty flag | `GET /api/version` (mirrors `stell_build_info{version,hash,dirty}`) |
| `node_id` | node identity (hex) | RPC `stell_nodeId`, also in `/api/version` |
| `ts` | snapshot unix time (for rate math) | snapshotter clock, not the node |

Publish cadence: every 30s. Keep the last N snapshots (e.g. 20) so
`finals_rate_10m` is computable from history. Render rule: if `syncing` is
true OR `finals_rate_10m == 0` for >10m, show DEGRADED (links to
`ops/alerts.md#finalsstalled`).

## Reference collector

`scripts/status_snapshot.sh` emits one JSON object with exactly the fields
above (plus `ok:false` + `error` on failure instead of fabricated values —
a node that cannot be reached reports "unknown", never a guessed height).
Point it at one node per cluster member and merge by `node_id` for a
multi-node page.

```bash
RPC_URL=http://127.0.0.1:18645 EXPLORER_URL=http://127.0.0.1:18080 \
  scripts/status_snapshot.sh
```
