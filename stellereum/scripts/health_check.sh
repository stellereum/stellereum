#!/usr/bin/env bash
# health_check.sh — read-only ops health check for a Stellereum node/stand.
#
# Checks (all read-only; writes nothing, changes nothing live):
#   1. height advancing — two `stell_blockNumber` samples INTERVAL apart
#      (default 6s) on each RPC port; equal samples = stalled.
#   2. mempool size — `stell_mempoolSize` per RPC port; >= MEMPOOL_CRIT
#      (default 9000, cap is 10000) counts as degraded.
#   3. disk usage — `df` on DISK_PATH (default /); >= DISK_CRIT (default 95)
#      counts as degraded, >= DISK_WARN (default 85) is reported but healthy.
#   4. REFUSING patterns — read-only scan of the journal
#      (`journalctl -u stell-nodeA/B`, when journalctl exists) or of the
#      node log files ($STELL_ROOT/nodeA/current.log, nodeB) for:
#        `genesis state root mismatch`, `lacks a validator quorum`,
#        `refusing to dispense`, `refusing to finalize`, `refusing to adopt`,
#        `admission refused`, `FINALIZE-BLOCKED`, `rejected proposal`.
#      Any match counts as degraded (the node is telling you it refuses work).
#
# Exit codes: 0 = healthy, 1 = degraded (alive but stalled/full/refusing),
#             2 = down (no height readable at all) or bad usage.
#
# Env overrides (all optional):
#   RPC_PORTS   space-separated RPC ports to poll (default "8545 8546")
#   EXPLORER_URL gateway base URL for an extra /healthz liveness note
#                (default http://127.0.0.1:8080; empty disables the note)
#   INTERVAL    seconds between the two height samples (default 6)
#   MEMPOOL_CRIT mempool entries at/above this = degraded (default 9000)
#   DISK_PATH   path for `df` (default /)
#   DISK_WARN / DISK_CRIT integer percents (default 85 / 95)
#   STELL_ROOT  node-dir root for log-file fallback (default /root)
#   JOURNAL_UNITS space-separated systemd units to scan (default
#                "stell-nodeA stell-nodeB")
#   LOG_LINES   journal/log lines scanned per source (default 500)
#
# Usage:
#   scripts/health_check.sh [--interval SECS] [--rpc PORTS] [--explorer URL]
#                           [--disk PATH] [--warn N] [--crit N]
# Examples:
#   scripts/health_check.sh
#   scripts/health_check.sh --interval 10 --rpc "8545" --disk /root
set -u

RPC_PORTS="${RPC_PORTS:-8545 8546}"
# Unset EXPLORER_URL uses the default; set it empty to disable the note.
# (${VAR-default} — not ${VAR:-default} — so "" stays "").
EXPLORER_URL="${EXPLORER_URL-http://127.0.0.1:8080}"
INTERVAL="${INTERVAL:-6}"
MEMPOOL_CRIT="${MEMPOOL_CRIT:-9000}"
DISK_PATH="${DISK_PATH:-/}"
DISK_WARN="${DISK_WARN:-85}"
DISK_CRIT="${DISK_CRIT:-95}"
ROOT="${STELL_ROOT:-/root}"
JOURNAL_UNITS="${JOURNAL_UNITS:-stell-nodeA stell-nodeB}"
LOG_LINES="${LOG_LINES:-500}"

while [ $# -gt 0 ]; do
  case "$1" in
    --interval) INTERVAL="${2:?--interval needs seconds}"; shift 2 ;;
    --rpc) RPC_PORTS="${2:?--rpc needs a port list}"; shift 2 ;;
    --explorer) EXPLORER_URL="${2:?--explorer needs a URL}"; shift 2 ;;
    --disk) DISK_PATH="${2:?--disk needs a path}"; shift 2 ;;
    --warn) DISK_WARN="${2:?--warn needs a percent}"; shift 2 ;;
    --crit) DISK_CRIT="${2:?--crit needs a percent}"; shift 2 ;;
    -h|--help)
      printf 'usage: %s [--interval SECS] [--rpc PORTS] [--explorer URL] [--disk PATH] [--warn N] [--crit N]\n' "$0"
      printf 'exits 0 healthy / 1 degraded / 2 down; read-only (HTTP GETs, one read-only RPC each, df, journalctl/log greps).\n'
      exit 2 ;;
    *) printf 'health_check.sh: unknown argument %s (see --help)\n' "$1" >&2; exit 2 ;;
  esac
done

case "$INTERVAL" in ''|*[!0-9]*) printf 'health_check.sh: --interval must be a non-negative integer\n' >&2; exit 2 ;; esac
case "$DISK_WARN" in ''|*[!0-9]*) printf 'health_check.sh: --warn must be an integer percent\n' >&2; exit 2 ;; esac
case "$DISK_CRIT" in ''|*[!0-9]*) printf 'health_check.sh: --crit must be an integer percent\n' >&2; exit 2 ;; esac

# rpc_field PORT FIELD — one read-only stell_blockNumber / stell_mempoolSize
# call; prints the raw result value (hex height or decimal mempool) or empty.
rpc_field() {
  local port="$1" method="$2" resp
  resp=$(curl -s -m 5 -X POST "http://127.0.0.1:$port" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":[]}" 2>/dev/null) || return 0
  printf '%s' "$resp" | awk -v m="$method" '
    {
      line = $0
      # "result": <value> where value is "0x.." (quoted) or a bare number
      if (match(line, /"result"[ \t]*:[ \t]*"[^"]*"/)) {
        v = substr(line, RSTART, RLENGTH)
        sub(/.*"result"[ \t]*:[ \t]*"/, "", v)
        sub(/".*/, "", v)
        print v
        exit
      }
      if (match(line, /"result"[ \t]*:[ \t]*[0-9]+/)) {
        v = substr(line, RSTART, RLENGTH)
        sub(/.*"result"[ \t]*:[ \t]*/, "", v)
        print v
        exit
      }
    }'
}

degraded=0
reasons=""

note_degraded() {
  degraded=1
  reasons="${reasons}${reasons:+; }$1"
}

echo "== stellereum health_check =="

# --- 0. liveness note (informational; never changes the exit code) ------------
if [ -n "$EXPLORER_URL" ]; then
  code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$EXPLORER_URL/healthz" 2>/dev/null || true)
  if [ -n "$code" ]; then
    printf 'liveness: GET /healthz -> HTTP %s\n' "$code"
  else
    printf 'liveness: gateway unreachable at %s (note only; RPC sampling decides)\n' "$EXPLORER_URL"
  fi
fi

# --- 1+2. two height samples + one mempool sample per RPC port ----------------
h1_all=""; h2_all=""; any_height=0
for port in $RPC_PORTS; do
  # shellcheck disable=SC2086
  h1=$(rpc_field "$port" "stell_blockNumber")
  m1=$(rpc_field "$port" "stell_mempoolSize")
  if [ -z "$h1" ]; then
    printf 'rpc %s: height unreadable (node RPC down?)\n' "$port"
    continue
  fi
  any_height=1
  printf 'rpc %s: height=%s mempool=%s\n' "$port" "$h1" "${m1:-?}"
  case "${m1:-}" in ''|*[!0-9]*) ;;
    *) if [ "$m1" -ge "$MEMPOOL_CRIT" ]; then
         printf 'rpc %s: mempool %s >= crit %s (pool near the 10000 cap)\n' "$port" "$m1" "$MEMPOOL_CRIT"
         note_degraded "mempool:$port=$m1"
       fi ;;
  esac
  # shellcheck disable=SC2086
  eval "H1_$port=\"\$h1\""
done

if [ "$any_height" -eq 0 ]; then
  printf 'DOWN: no height readable on any RPC port (%s)\n' "$RPC_PORTS"
  exit 2
fi

sleep "$INTERVAL"

for port in $RPC_PORTS; do
  # shellcheck disable=SC2086
  eval "h1=\"\$H1_$port\""
  [ -z "${h1:-}" ] && continue  # port was unreadable in round one; already reported
  h2=$(rpc_field "$port" "stell_blockNumber")
  if [ -z "$h2" ]; then
    printf 'rpc %s: second height sample failed (first was %s)\n' "$port" "$h1"
    note_degraded "resample:$port"
    continue
  fi
  printf 'rpc %s: height %s -> %s over %ss\n' "$port" "$h1" "$h2" "$INTERVAL"
  if [ "$h1" = "$h2" ]; then
    case "$h1" in 0|0x0|0X0)
      printf 'rpc %s: height_zero — stuck at 0 over %ss (pre-consensus?)\n' "$port" "$INTERVAL" ;;
    *) printf 'rpc %s: STALLED — height %s unchanged over %ss\n' "$port" "$h1" "$INTERVAL" ;;
    esac
    note_degraded "stalled:$port=$h1"
  fi
  h2_all="$h2_all $h2"
  h1_all="$h1_all $h1"
done

# --- 3. disk usage (read-only df) ---------------------------------------------
disk_pct=$(df -P "$DISK_PATH" 2>/dev/null | awk 'NR==2 { gsub(/%/, "", $5); print $5 }')
if [ -z "$disk_pct" ]; then
  printf 'disk: df unreadable for %s (skipping disk check)\n' "$DISK_PATH"
else
  printf 'disk: %s at %s%% (warn>=%s crit>=%s)\n' "$DISK_PATH" "$disk_pct" "$DISK_WARN" "$DISK_CRIT"
  case "$disk_pct" in ''|*[!0-9]*) ;;
    *) if [ "$disk_pct" -ge "$DISK_CRIT" ]; then
         printf 'disk: CRITICAL — %s%% >= %s%% (free space before any restart/wipe)\n' "$disk_pct" "$DISK_CRIT"
         note_degraded "disk=$disk_pct"
       elif [ "$disk_pct" -ge "$DISK_WARN" ]; then
         printf 'disk: warning — %s%% >= %s%% (journal + stale *.log are the usual drivers)\n' "$disk_pct" "$DISK_WARN"
       fi ;;
  esac
fi

# --- 4. REFUSING patterns (read-only journal/log scan) ------------------------
REFUSING_RE='genesis state root mismatch|lacks a validator quorum|refusing to dispense|refusing to finalize|refusing to adopt|admission refused|FINALIZE-BLOCKED|rejected proposal'
found_refusing=0
if command -v journalctl >/dev/null 2>&1; then
  for unit in $JOURNAL_UNITS; do
    hits=$(journalctl -u "$unit" --no-pager -n "$LOG_LINES" 2>/dev/null | grep -cE "$REFUSING_RE" || true)
    case "$hits" in ''|*[!0-9]*) hits=0 ;; esac
    if [ "$hits" -gt 0 ]; then
      printf 'journal %s: %s REFUSING-pattern line(s) in last %s lines\n' "$unit" "$hits" "$LOG_LINES"
      journalctl -u "$unit" --no-pager -n "$LOG_LINES" 2>/dev/null | grep -E "$REFUSING_RE" | tail -5
      found_refusing=1
    else
      printf 'journal %s: no REFUSING patterns in last %s lines\n' "$unit" "$LOG_LINES"
    fi
  done
else
  printf 'journal: journalctl absent; falling back to log files under %s\n' "$ROOT"
fi
# Log-file fallback always runs when journalctl gave nothing (absent journal,
# missing units, or ephemeral containers): read-only grep over current.log.
if [ "$found_refusing" -eq 0 ]; then
  for dir in "$ROOT/nodeA" "$ROOT/nodeB"; do
    log="$dir/current.log"
    if [ -f "$log" ]; then
      hits=$(grep -cE "$REFUSING_RE" "$log" 2>/dev/null || true)
      case "$hits" in ''|*[!0-9]*) hits=0 ;; esac
      if [ "$hits" -gt 0 ]; then
        printf 'log %s: %s REFUSING-pattern line(s)\n' "$log" "$hits"
        grep -E "$REFUSING_RE" "$log" 2>/dev/null | tail -5
        found_refusing=1
      else
        printf 'log %s: no REFUSING patterns\n' "$log"
      fi
    else
      printf 'log %s: absent (skipped)\n' "$log"
    fi
  done
fi
if [ "$found_refusing" -eq 1 ]; then
  note_degraded "refusing-patterns"
fi

if [ "$degraded" -eq 1 ]; then
  printf 'DEGRADED: %s\n' "$reasons"
  exit 1
fi
printf 'HEALTHY: heights advancing, mempool below %s, disk below %s%%, no REFUSING patterns\n' "$MEMPOOL_CRIT" "$DISK_CRIT"
exit 0
