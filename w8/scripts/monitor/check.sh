#!/usr/bin/env bash
# check.sh — dependency-free (curl + awk only) health check for a Stellereum node.
#
# Queries /healthz (liveness), /readyz (readiness with named failure reasons)
# and /metrics (stell_ready gauge + stell_consensus_height) of one gateway,
# plus an optional JSON-RPC endpoint for an independent height sample.
#
# Exit codes:  0 = healthy   1 = degraded (alive but not ready / stalled / no peers)
#              2 = down (process unreachable) or bad usage.
#
# Distinguishes:
#   process down      — no TCP/HTTP response at all (curl cannot connect).
#   alive-but-not-ready — /readyz answers 503 and names the reason
#                         (no_peers | no_finality | finality_stalled |
#                          height_zero | height_stalled).
#   stalled           — height identical across two samples INTERVAL apart
#                       (RPC stell_blockNumber when --rpc is given, else the
#                       stell_consensus_height gauge from /metrics).
#   no peers          — /readyz failed_checks contains no_peers.
#
# Legacy binaries (such as the one live on 2026-09-26) answer 404 on
# /healthz and /readyz and export no stell_ready gauge. Any HTTP response —
# even 404 — still proves the process is alive, so this script treats
# "connection failed" (not "non-200") as DOWN and falls back to the
# /metrics + RPC height-sampling path when /readyz is absent.
#
# Usage:
#   check.sh [--explorer URL] [--rpc PORT] [--interval SECS] [--stall SECS]
#
#   --explorer URL   gateway base URL (default http://127.0.0.1:8080)
#   --rpc PORT       JSON-RPC port for stell_blockNumber stall sampling
#                    (default: unset — sample /metrics twice instead)
#   --interval SECS  seconds between the two height samples (default 6)
#   --stall SECS     stall reference in seconds, for messages only
#                    (default 30 = STELL_READY_MAX_STALL_SECS default in
#                    src/explorer.rs; the node itself enforces it in /readyz)
#
# Read-only: performs only HTTP GETs and one read-only RPC method
# (stell_blockNumber). Writes nothing to disk and changes nothing live.
set -u

EXPLORER="http://127.0.0.1:8080"
RPC_PORT=""
INTERVAL=6
STALL_REF=30

while [ $# -gt 0 ]; do
    case "$1" in
        --explorer) EXPLORER="${2:-}"; shift 2 ;;
        --rpc) RPC_PORT="${2:-}"; shift 2 ;;
        --interval) INTERVAL="${2:-6}"; shift 2 ;;
        --stall) STALL_REF="${2:-30}"; shift 2 ;;
        -h|--help)
            printf 'usage: %s [--explorer URL] [--rpc PORT] [--interval SECS] [--stall SECS]\n' "$0"
            printf 'exits 0 healthy / 1 degraded / 2 down; prints the failing reason.\n'
            exit 2 ;;
        *) printf 'check.sh: unknown argument %s (see --help)\n' "$1"; exit 2 ;;
    esac
done

# http_get PATH — GET a gateway path; prints "HTTP <code> <body>".
# The body is flattened to one line with awk (axum JSON bodies have no
# newlines; /metrics does, so flattening keeps the "one line" contract).
# Uses only curl + awk + shell builtins. Writes nothing to disk.
http_get() {
    local path="$1" out rc code body
    out=$(curl -s -m 5 -w '\n%{http_code}' "$EXPLORER$path" 2>/dev/null)
    rc=$?
    if [ "$rc" -ne 0 ]; then
        printf 'CURL_FAIL %s\n' "$rc"
        return 0
    fi
    code=$(printf '%s' "$out" | awk '{ last=$0 } END { print last }')
    body=$(printf '%s' "$out" | awk 'NR==1 {first=1} { lines[NR]=$0 } END { for (i=1;i<NR;i++) { gsub(/\r/, "", lines[i]); printf "%s%s", lines[i], (i<NR-1 ? " " : "") } }')
    printf 'HTTP %s %s\n' "$code" "$body"
}

# rpc_height — print the hex stell_blockNumber result (e.g. 0xc2) or empty.
# Tolerates optional whitespace around the JSON colon.
rpc_height() {
    local port="$1" resp
    resp=$(curl -s -m 5 -X POST "http://127.0.0.1:$port" \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}' 2>/dev/null) || return 0
    printf '%s' "$resp" | awk '{ line=$0; if (sub(/.*"result"[ \t]*:[ \t]*"/, "", line)) { sub(/".*/, "", line); print line } }'
}

# metric_value TEXT NAME — first sample value of a gauge in exposition text.
metric_value() {
    printf '%s' "$1" | awk -v name="$2" '$1 == name { print $2; exit }'
}

# rpc_note READYZ_HEIGHT — one independent stell_blockNumber sample when
# --rpc was given. The shared :8080 gateway sees only whichever node won the
# bind, so the RPC port is the per-node view (e.g. A=0x0 vs B=0x16f while the
# gateway reports one height). Informational only; never changes the exit code.
rpc_note() {
    local rh="$1" h dec
    [ -z "$RPC_PORT" ] && return 0
    h=$(rpc_height "$RPC_PORT")
    if [ -z "$h" ]; then
        printf 'rpc: stell_blockNumber(:%s) unreadable (node RPC down?)\n' "$RPC_PORT"
        return 0
    fi
    printf 'rpc: stell_blockNumber(:%s)=%s (gateway height=%s)\n' "$RPC_PORT" "$h" "${rh:-?}"
    case "$h" in 0x*|0X*) dec=$((h)) 2>/dev/null || return 0 ;; ''|*[!0-9]*) return 0 ;; *) dec=$h ;; esac
    case "${rh:-}" in ''|*[!0-9]*) return 0 ;; esac
    if [ "$dec" != "$rh" ]; then
        printf 'warning: RPC height %s != gateway height %s — nodes diverged or gateway serves the other node (shared :8080 binds once)\n' "$dec" "$rh"
    fi
}

echo "== stellereum check: $EXPLORER =="

# --- 1. liveness: any HTTP answer (even 404 on legacy binaries) = alive ------
probe=$(http_get "/healthz")
case "$probe" in
    CURL_FAIL*)
        rc=$(printf '%s' "$probe" | awk '{print $2}')
        printf 'DOWN: process unreachable at %s (curl rc=%s; connection refused/timeout)\n' "$EXPLORER" "$rc"
        exit 2
        ;;
esac
probe_code=$(printf '%s' "$probe" | awk '{print $2}')
printf 'liveness: process alive (GET /healthz -> HTTP %s)\n' "$probe_code"

# --- 2. readiness: /readyz names the failing condition when present ----------
readyz=$(http_get "/readyz")
readyz_code=$(printf '%s' "$readyz" | awk '{print $2}')
readyz_body=$(printf '%s' "$readyz" | awk '{sub(/^HTTP [0-9]+ /, ""); print}')

if [ "$readyz_code" = "200" ]; then
    rh=$(printf '%s' "$readyz_body" | awk -F'"height":' '{if (NF>1){split($2,a,/[^0-9]/); print a[1]}}')
    rp=$(printf '%s' "$readyz_body" | awk -F'"peers":' '{if (NF>1){split($2,a,/[^0-9]/); print a[1]}}')
    printf 'HEALTHY: /readyz 200 (height=%s peers=%s)\n' "${rh:-?}" "${rp:-?}"
    rpc_note "${rh:-}"
    exit 0
elif [ "$readyz_code" = "503" ]; then
    reasons=$(printf '%s' "$readyz_body" | awk -F'"failed_checks":' '
        NF > 1 {
            s = $2
            sub(/\].*/, "", s)
            gsub(/[^a-z_,]/, " ", s)
            gsub(/ +/, " ", s)
            gsub(/^ | $/, "", s)
            print s
        }')
    rh=$(printf '%s' "$readyz_body" | awk -F'"height":' '{if (NF>1){split($2,a,/[^0-9]/); print a[1]}}')
    printf 'DEGRADED: alive but NOT ready (height=%s; failed_checks: %s)\n' "${rh:-?}" "${reasons:-unknown}"
    case " $reasons " in
        *no_peers*) printf 'reason: no_peers — node holds no peer connection (check DHT/peers in logs)\n' ;;
    esac
    case " $reasons " in
        *no_finality*) printf 'reason: no_finality — nothing ever finalized (pre-consensus / DHT warmup?)\n' ;;
    esac
    case " $reasons " in
        *finality_stalled*) printf 'reason: finality_stalled — no finalize for >%ss (view-change spin with zero finalizes?)\n' "$STALL_REF" ;;
    esac
    case " $reasons " in
        *height_zero*) printf 'reason: height_zero — RPC answering at height 0 (stuck pre-consensus)\n' ;;
    esac
    case " $reasons " in
        *height_stalled*) printf 'reason: height_stalled — height not advancing for >%ss\n' "$STALL_REF" ;;
    esac
    rpc_note "${rh:-}"
    exit 1
else
    printf 'note: /readyz -> HTTP %s (legacy binary without readiness probes?); falling back to /metrics + height sampling\n' "$readyz_code"
fi

# --- 3. legacy path: /metrics + two height samples ---------------------------
metrics=$(http_get "/metrics")
metrics_code=$(printf '%s' "$metrics" | awk '{print $2}')
if [ "$metrics_code" != "200" ]; then
    printf 'DEGRADED: process alive but /metrics unavailable (HTTP %s); cannot assess readiness\n' "$metrics_code"
    exit 1
fi
metrics_body=$(printf '%s' "$metrics" | awk '{sub(/^HTTP [0-9]+ /, ""); print}')

m_h1=$(metric_value "$metrics_body" "stell_consensus_height")
[ -z "$m_h1" ] && m_h1=$(metric_value "$metrics_body" "stellereum_block_height")
m_ready=$(metric_value "$metrics_body" "stell_ready")
m_round=$(metric_value "$metrics_body" "stell_consensus_round")
m_val=$(metric_value "$metrics_body" "stell_validator_set_size")

if [ -n "$m_ready" ]; then
    if [ "$m_ready" = "1" ]; then
        printf 'HEALTHY: stell_ready 1 (height=%s round=%s)\n' "${m_h1:-?}" "${m_round:-?}"
        exit 0
    else
        printf 'DEGRADED: stell_ready 0 (height=%s round=%s validator_set=%s)\n' \
            "${m_h1:-?}" "${m_round:-?}" "${m_val:-?}"
        printf 'hint: curl %s/readyz for the named failed_checks\n' "$EXPLORER"
        exit 1
    fi
fi
printf 'note: no stell_ready gauge on this binary (pre-readiness build); using height-advance sampling\n'

sample_height() {
    if [ -n "$RPC_PORT" ]; then
        rpc_height "$RPC_PORT"
    else
        m=$(http_get "/metrics")
        b=$(printf '%s' "$m" | awk '{sub(/^HTTP [0-9]+ /, ""); print}')
        v=$(metric_value "$b" "stell_consensus_height")
        [ -z "$v" ] && v=$(metric_value "$b" "stellereum_block_height")
        printf '%s' "$v"
    fi
}

h1=$(sample_height)
if [ -z "$h1" ]; then
    printf 'DEGRADED: process alive but height unreadable (RPC %s / /metrics gave nothing)\n' "${RPC_PORT:-<no --rpc>}"
    exit 1
fi
sleep "$INTERVAL"
h2=$(sample_height)
if [ -z "$h2" ]; then
    printf 'DEGRADED: second height sample failed (first was %s)\n' "$h1"
    exit 1
fi

if [ "$h1" != "$h2" ]; then
    printf 'HEALTHY (legacy probe): height advancing %s -> %s over %ss (readiness probes unavailable on this binary)\n' "$h1" "$h2" "$INTERVAL"
    printf 'caveat: peers unobservable here — no peer metric/RPC is exported; grep logs for peer/DHT lines\n'
    exit 0
fi

# Height identical across both samples.
if [ "$h1" = "0" ] || [ "$h1" = "0x0" ]; then
    printf 'DEGRADED: height_zero — height 0 unchanged over %ss (stuck pre-consensus / DHT warmup; cf. readyz height_zero+no_finality)\n' "$INTERVAL"
    exit 1
fi
printf 'DEGRADED: stalled — height %s unchanged over %ss (cf. readyz finality_stalled/height_stalled, N=%ss)\n' "$h1" "$INTERVAL" "$STALL_REF"
[ -n "$m_round" ] && printf 'detail: stell_consensus_round=%s validator_set_size=%s (round spinning with zero finalizes => view-change spin)\n' "$m_round" "${m_val:-?}"
printf 'caveat: peers unobservable here — no peer metric/RPC is exported; grep logs for peer/DHT lines\n'
exit 1
