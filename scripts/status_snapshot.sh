#!/usr/bin/env bash
# status_snapshot.sh — emit one JSON object describing this node's public status.
#
# Uses ONLY endpoints verified to exist (2026-11-02):
#   RPC (default $RPC_URL, STELL_RPC_LISTEN default 127.0.0.1:8545):
#     eth_blockNumber, stell_syncing, stell_getStateRoot, stell_getValidators,
#     stell_mempoolSize, stell_chainId, stell_nodeId
#     (verified via: rg -o '"(stell|eth)_[A-Za-z0-9]+"' stellereum/src/rpc.rs)
#   Explorer (default $EXPLORER_URL, STELL_EXPLORER_LISTEN default 127.0.0.1:8080):
#     GET /api/version, GET /metrics (stell_consensus_height cross-check)
#
# Never fabricates: unreachable node -> {"ok":false,...}, never guessed values.
#
# Usage:
#   scripts/status_snapshot.sh
#   RPC_URL=http://127.0.0.1:18645 EXPLORER_URL=http://127.0.0.1:18080 scripts/status_snapshot.sh
#
set -euo pipefail

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
EXPLORER_URL="${EXPLORER_URL:-http://127.0.0.1:8080}"
TIMEOUT=5

rpc() { # $1 = method, $2 = params json
    curl -s -m "$TIMEOUT" -X POST -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" \
        "$RPC_URL" 2>/dev/null || echo ""
}

TS="$(date +%s)"
HEIGHT_HEX="$(rpc eth_blockNumber | grep -oE '"result":"0x[0-9a-fA-F]+"' | head -1 | grep -oE '0x[0-9a-fA-F]+' || true)"
SYNCING="$(rpc stell_syncing || true)"
STATE_ROOT="$(rpc stell_getStateRoot || true)"
VALIDATORS="$(rpc stell_getValidators || true)"
MEMPOOL="$(rpc stell_mempoolSize || true)"
CHAIN_ID="$(rpc stell_chainId || true)"
NODE_ID="$(rpc stell_nodeId || true)"
VERSION_JSON="$(curl -s -m "$TIMEOUT" "$EXPLORER_URL/api/version" 2>/dev/null || echo "")"
METRICS_HEIGHT="$(curl -s -m "$TIMEOUT" "$EXPLORER_URL/metrics" 2>/dev/null | grep -E '^stell_consensus_height ' | awk '{print $2}' | head -1 || true)"

export TS HEIGHT_HEX SYNCING STATE_ROOT VALIDATORS MEMPOOL CHAIN_ID NODE_ID VERSION_JSON METRICS_HEIGHT
python3 - "$RPC_URL" "$EXPLORER_URL" <<'EOF'
import json, os, sys

def rpc_result(raw):
    try:
        d = json.loads(raw)
    except Exception:
        return None
    return d.get("result", None)

def hexint(v):
    try:
        return int(v, 16) if isinstance(v, str) and v.startswith("0x") else (int(v) if isinstance(v, int) else None)
    except Exception:
        return None

rpc_url, explorer_url = sys.argv[1], sys.argv[2]
height = hexint(os.environ.get("HEIGHT_HEX") or "")
validators = rpc_result(os.environ.get("VALIDATORS") or "")
n_validators = len(validators) if isinstance(validators, list) else None
try:
    version = json.loads(os.environ.get("VERSION_JSON") or "")
    if not isinstance(version, dict):
        version = None
except Exception:
    version = None
try:
    mh = os.environ.get("METRICS_HEIGHT") or ""
    metrics_height = int(float(mh)) if mh.strip() else None
except Exception:
    metrics_height = None

out = {
    "ok": height is not None,
    "ts": int(os.environ.get("TS") or 0),
    "rpc_url": rpc_url,
    "explorer_url": explorer_url,
    "height": height,
    "metrics_height": metrics_height,
    "heights_agree": (height is not None and metrics_height is not None and height == metrics_height),
    "syncing": rpc_result(os.environ.get("SYNCING") or ""),
    "state_root": rpc_result(os.environ.get("STATE_ROOT") or ""),
    "validators": n_validators,
    "mempool": rpc_result(os.environ.get("MEMPOOL") or ""),
    "chain_id": rpc_result(os.environ.get("CHAIN_ID") or ""),
    "node_id": rpc_result(os.environ.get("NODE_ID") or ""),
    "version": version,
}
if height is None:
    out["error"] = f"unreachable or bad eth_blockNumber from {rpc_url} (no values fabricated)"
print(json.dumps(out, indent=2))
EOF
