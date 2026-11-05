#!/usr/bin/env bash
# Stall watchdog for the 2-node Stellereum stand.
# Restarts are the proven recovery for transport stalls (ghost conns) and
# asymmetric states: every stall to date cleared on a clean restart, while
# manual debugging takes hours. This automates the crutch honestly:
#   - polls both RPCs for block height every 30s
#   - if NEITHER advances for STALL_SECS (default 180), graceful-restarts
#     both nodes (SIGTERM -> 20s drain (flush needs 15s) -> verify dead -> start)
#   - logs every decision; never wipes data (use wipe+start manually for forks)
# Run: nohup /root/stall_watchdog.sh >>/root/watchdog.log 2>&1 &
# Env overrides (all optional, defaults are the live stand):
#   RPC_A / RPC_B       per-node JSON-RPC URLs (default 127.0.0.1:8545/8546)
#   POLL_SECS           seconds between height polls (default 30)
#   STALL_SECS          seconds with no advance before a restart (default 180)
#   WATCHDOG_LOG        decision log (default /root/watchdog.log)
#   STELL_NODE_SH       control script used for `restart`
#                       (default /root/stell-node.sh)
# `WATCHDOG_LOG`/`STELL_NODE_SH` exist so the script is dry-runnable off-host
# (single-host convention: STELL_ROOT is NOT used here because the stand keeps
# the control script + log at fixed /root paths, not under STELL_ROOT).
# Usage: stall_watchdog.sh [-h|--help]   (anything else starts watching)
set -u
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  printf 'usage: %s [-h|--help]\n' "$0"
  printf 'polls both RPCs every POLL_SECS; restarts via STELL_NODE_SH when neither advances for STALL_SECS.\n'
  printf 'env: RPC_A RPC_B POLL_SECS STALL_SECS WATCHDOG_LOG STELL_NODE_SH\n'
  exit 2
fi
RPC_A="${RPC_A:-http://127.0.0.1:8545/}"
RPC_B="${RPC_B:-http://127.0.0.1:8546/}"
POLL_SECS="${POLL_SECS:-30}"
STALL_SECS="${STALL_SECS:-180}"
LOG="${WATCHDOG_LOG:-/root/watchdog.log}"
NODE_SH="${STELL_NODE_SH:-/root/stell-node.sh}"

height() {
  curl -s -m 10 -X POST "$1" --header "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"stell_blockNumber","params":[],"id":1}' \
    | grep -o '"result":"0x[0-9a-f]*"' | grep -o '0x[0-9a-f]*' | head -1
}

log() { echo "$(date -u +%FT%TZ) [watchdog] $*" >>"$LOG"; }

last_change=$(date +%s)
last_a=""
last_b=""
log "started (poll=${POLL_SECS}s stall=${STALL_SECS}s)"

while true; do
  sleep "$POLL_SECS"
  # Dead processes are stell-node.sh's problem, not ours; just report.
  pa=$(ps -eo args | grep -c "[s]tellereum run" || true)
  if [ "$pa" -lt 2 ]; then
    log "only $pa process(es) alive; NOT restarting (operator owns process crashes)"
    continue
  fi
  a=$(height "$RPC_A"); b=$(height "$RPC_B")
  if [ "$a" != "$last_a" ] || [ "$b" != "$last_b" ]; then
    last_a="$a"; last_b="$b"; last_change=$(date +%s)
    continue
  fi
  idle=$(( $(date +%s) - last_change ))
  if [ "$idle" -ge "$STALL_SECS" ]; then
    log "STALL: no progress for ${idle}s (A=$a B=$b); graceful restart"
    # Delegate to stell-node.sh restart: SIGTERM -> wait up to 30s for drain
    # -> SIGKILL+5s -> start only when zero processes remain. Do NOT hand-roll
    # kill+sleep here: a fixed sleep races the drain and plain `start` now
    # refuses when old processes linger (exit 2) to prevent duplicate writers.
    "$NODE_SH" restart >>"$LOG" 2>&1 || log "restart FAILED"
    last_change=$(date +%s)
    log "restarted; watching again"
  fi
done
