#!/usr/bin/env bash
# ==============================================================================
# cluster_liveness.sh — read-only cluster liveness / divergence detector.
#
# Answers the only three questions that matter during an incident:
#   1. Is the reachable cluster tip advancing?
#   2. Do reachable endpoints agree on the height (within one block)?
#   3. If not, WHY: health verdict, round, finalized height, peers, and the
#      last rejected-proposal reasons from the node journals.
#
# This script NEVER writes, restarts, prunes, or clears anything. It only:
#   * POSTs read-only JSON-RPC (`stell_blockNumber`, `stell_getBlock`, ...);
#   * GETs `/health` when a gateway URL is supplied;
#   * runs the operator-supplied journal command (read-only).
#
# Exit codes:
#   0  OK
#   1  STALLED  (no height change for > stall-factor * expected block time,
#                 every endpoint unreachable, or configured minimum not met)
#   2  DIVERGED (heights differ by more than one block, a height regressed, or
#                 two nodes serve different block hashes at a common height)
#  64  usage / configuration error
#
# Machine-readable last line:
#   LIVENESS_RESULT=OK|STALLED|DIVERGED height=... spread=... ...
#
# Endpoint syntax (env STELL_RPCS or --rpcs):
#   "A=http://127.0.0.1:8545,B=http://127.0.0.1:8546"
# Optional per-node health gateway / extra diagnostics:
#   "A=http://127.0.0.1:8545;health=http://127.0.0.1:8080,B=..."
# STELL_HEALTH_RPCS can override the health URL after parsing:
#   "A=http://127.0.0.1:8080,B=http://127.0.0.1:8081"
#
# Journal diagnostics (optional, repeatable; a bare value applies to all):
#   --journal "ssh root@host journalctl -u stell-nodeA"
#   --journal 'A=ssh root@host journalctl -u stell-nodeA'
#   --journal 'B=journalctl --user -u stell-nodeB'
# Do not pass `-f`; the script appends `--no-pager -n <scan>` for journalctl.
# ==============================================================================
set -uo pipefail

PROG="$(basename "$0")"
INTERVAL=5
WINDOW=60
EXPECTED_BLOCK_TIME=5
STALL_FACTOR=3
RPC_TIMEOUT=5
JOURNAL_SCAN=2000
JOURNAL_LAST=10
MIN_REACHABLE=""

RPCS_SPEC="${STELL_RPCS:-}"
HEALTH_SPEC="${STELL_HEALTH_RPCS:-}"
JOURNAL_GLOBAL=""

declare -a NAMES=()
declare -A RPC_URL=()
declare -A HEALTH_URL=()
declare -A JOURNAL_CMD=()

usage() {
    cat <<EOF
$PROG — read-only liveness / divergence detector for a Stellereum cluster

USAGE
  STELL_RPCS="A=http://127.0.0.1:8545,B=http://127.0.0.1:8546" $PROG [options]
  $PROG --rpcs "A=...,B=..." [options]

OPTIONS
  --rpcs SPEC            endpoints (default: \$STELL_RPCS)
  --health-rpcs SPEC     per-node /health gateways (default: rpc URL itself)
  --interval SEC         poll interval (default $INTERVAL)
  --window SEC           observation window (default $WINDOW)
  --expected-block-time SEC
                         expected block time (default $EXPECTED_BLOCK_TIME)
  --stall-factor N       stall threshold = N * expected block time
                         (default $STALL_FACTOR)
  --timeout SEC          per-RPC HTTP timeout (default $RPC_TIMEOUT)
  --min-reachable N      require at least N endpoints with valid heights in the
                         final poll (default: 1; partial reachability allowed)
  --journal CMD          journal command for rejected-proposal reasons
                         ("ssh host journalctl -u stell-nodeA"; repeatable,
                         or may be written as NAME=CMD for one node)
  --journal-last N       print the last N rejected proposals (default $JOURNAL_LAST)
  --journal-scan N       journalctl -n lookback (default $JOURNAL_SCAN)
  --help                 this text

VERDICTS
  OK        reachable tip not stalled, spread <= 1, no hash mismatch detected,
            and the configured minimum of reachable endpoints is met
  STALLED   cluster tip unchanged for > stall-factor * expected block time,
            every endpoint is unreachable, or minimum reachability is not met
  DIVERGED  heights differ by more than 1, a height regressed, or the
            reachable nodes disagree on the block hash at a common height

NOTES
  * This tool is strictly read-only: no writes, no restarts, no lock clears.
  * Reachability means a valid RPC height in the final poll; it is not a
    validator count or P2P peer count. Hash lookup failures do not fail OK.
  * /health lives on the gateway HTTP port, not necessarily the JSON-RPC port.
    Supply --health-rpcs (or ;health=... in --rpcs) when they differ.
  * Rejected-proposal log line used: "[consensus] rejected proposal from ...".
  * Secrets in journal lines are redacted before printing.

EXAMPLES
  $PROG --rpcs "A=http://127.0.0.1:8545,B=http://127.0.0.1:8546" \\
        --health-rpcs "A=http://127.0.0.1:8080,B=http://127.0.0.1:8081" \\
        --journal "A=ssh root@host journalctl -u stell-nodeA" --window 90

  $PROG --rpcs "\$STELL_RPCS" --interval 2 --window 30 --expected-block-time 1
EOF
}

die() {
    printf '%s: %s\n' "$PROG" "$*" >&2
    exit 64
}

need_value() {
    [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
}

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# ---- argument parsing -------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rpcs)             need_value "$@"; RPCS_SPEC="$2"; shift 2 ;;
        --health-rpcs)      need_value "$@"; HEALTH_SPEC="$2"; shift 2 ;;
        --interval)         need_value "$@"; INTERVAL="$2"; shift 2 ;;
        --window)           need_value "$@"; WINDOW="$2"; shift 2 ;;
        --expected-block-time) need_value "$@"; EXPECTED_BLOCK_TIME="$2"; shift 2 ;;
        --stall-factor)     need_value "$@"; STALL_FACTOR="$2"; shift 2 ;;
        --timeout)          need_value "$@"; RPC_TIMEOUT="$2"; shift 2 ;;
        --min-reachable)    need_value "$@"; MIN_REACHABLE="$2"; shift 2 ;;
        --journal-last)     need_value "$@"; JOURNAL_LAST="$2"; shift 2 ;;
        --journal-scan)     need_value "$@"; JOURNAL_SCAN="$2"; shift 2 ;;
        --journal)
            need_value "$@"
            if [[ "$2" =~ ^[A-Za-z0-9_.-]+= ]]; then
                JOURNAL_CMD["${2%%=*}"]="${2#*=}"
            else
                JOURNAL_GLOBAL="$2"
            fi
            shift 2 ;;
        --help|-h)          usage; exit 0 ;;
        *)                  die "unknown option: $1 (try --help)" ;;
    esac
done

[[ -n "$RPCS_SPEC" ]] || die "no endpoints: set STELL_RPCS or pass --rpcs"
[[ "$INTERVAL" =~ ^[1-9][0-9]*$ ]] || die "--interval must be a positive integer"
[[ "$WINDOW" =~ ^[1-9][0-9]*$ ]] || die "--window must be a positive integer"
[[ "$EXPECTED_BLOCK_TIME" =~ ^[1-9][0-9]*$ ]] || die "--expected-block-time must be a positive integer"
[[ "$STALL_FACTOR" =~ ^[1-9][0-9]*$ ]] || die "--stall-factor must be a positive integer"
[[ "$RPC_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "--timeout must be a positive integer"
[[ "$JOURNAL_LAST" =~ ^[1-9][0-9]*$ ]] || die "--journal-last must be a positive integer"
[[ "$JOURNAL_SCAN" =~ ^[1-9][0-9]*$ ]] || die "--journal-scan must be a positive integer"
if [[ -n "$MIN_REACHABLE" ]]; then
    [[ "$MIN_REACHABLE" =~ ^[1-9][0-9]*$ ]] || die "--min-reachable must be a positive integer"
fi

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v jq   >/dev/null 2>&1 || die "jq is required (JSON-RPC / health parsing)"

STALL_SECS=$((STALL_FACTOR * EXPECTED_BLOCK_TIME))
if (( WINDOW < STALL_SECS )); then
    printf '%s: warning: --window %ss is shorter than the stall threshold %ss; a stall shorter than the window cannot be proven.\n' \
        "$PROG" "$WINDOW" "$STALL_SECS" >&2
fi

# ---- endpoint parsing -------------------------------------------------------
# Split "A=url;health=url" on ';' so URLs keep their colons.
parse_endpoints() {
    local spec="$1" health_spec="$2"
    local entry name rest first extras kv key val
    local -a entries pairs

    IFS=',' read -r -a entries <<< "$spec"
    for entry in "${entries[@]}"; do
        entry="$(trim "$entry")"
        [[ -n "$entry" ]] || continue
        [[ "$entry" == *=* ]] || die "bad endpoint entry (want NAME=URL): $entry"
        name="$(trim "${entry%%=*}")"
        rest="$(trim "${entry#*=}")"
        [[ -n "$name" && -n "$rest" ]] || die "bad endpoint entry: $entry"
        [[ -z "${RPC_URL[$name]:-}" ]] || die "duplicate endpoint name: $name"

        first="${rest%%;*}"
        extras=""
        [[ "$rest" == *';'* ]] && extras="${rest#*;}"
        RPC_URL["$name"]="$first"
        HEALTH_URL["$name"]="$first"
        NAMES+=("$name")

        if [[ -n "$extras" ]]; then
            IFS=';' read -r -a pairs <<< "$extras"
            for kv in "${pairs[@]}"; do
                [[ -n "$kv" ]] || continue
                [[ "$kv" == *=* ]] || die "bad endpoint attribute (want key=value): $kv"
                key="$(trim "${kv%%=*}")"
                val="$(trim "${kv#*=}")"
                case "$key" in
                    health) HEALTH_URL["$name"]="$val" ;;
                    *)      die "unknown endpoint attribute: $key" ;;
                esac
            done
            unset pairs
        fi
    done

    # A separate --health-rpcs / STELL_HEALTH_RPCS wins for named nodes.
    if [[ -n "$health_spec" ]]; then
        IFS=',' read -r -a entries <<< "$health_spec"
        for entry in "${entries[@]}"; do
            entry="$(trim "$entry")"
            [[ -n "$entry" ]] || continue
            [[ "$entry" == *=* ]] || die "bad health entry (want NAME=URL): $entry"
            name="$(trim "${entry%%=*}")"
            val="$(trim "${entry#*=}")"
            [[ -n "${RPC_URL[$name]:-}" ]] || die "health URL names an unknown node: $name"
            HEALTH_URL["$name"]="$val"
        done
    fi
}

parse_endpoints "$RPCS_SPEC" "$HEALTH_SPEC"

if [[ -n "$MIN_REACHABLE" ]]; then
    endpoint_count="${#NAMES[@]}"
    # Compare lengths first so an oversized input cannot overflow shell arithmetic.
    if (( ${#MIN_REACHABLE} > ${#endpoint_count} )) ||
       { (( ${#MIN_REACHABLE} == ${#endpoint_count} )) && [[ "$MIN_REACHABLE" > "$endpoint_count" ]]; }; then
        die "--min-reachable exceeds configured endpoint count ($endpoint_count)"
    fi
fi

for jname in "${!JOURNAL_CMD[@]}"; do
    [[ -n "${RPC_URL[$jname]:-}" ]] || die "--journal names an unknown node: $jname"
done

# ---- redaction --------------------------------------------------------------
redact_url() {
    sed -E 's#(https?://)[^/@[:space:]]+@#\1***@#g'
}

redact_line() {
    sed -E \
        -e 's/((TOKEN|SECRET|PASS|PASSWORD|PASSPHRASE|PRIVATE)[A-Z0-9_]*)[=:][^[:space:]]+/\1=<redacted>/Ig' \
        -e 's#(https?://)[^/@[:space:]]+@#\1***@#g'
}

# ---- RPC helpers ------------------------------------------------------------
rpc_call() { # url method params-json
    local url="$1" method="$2" params="$3"
    local payload
    payload="$(printf '{"jsonrpc":"2.0","id":1,"method":"%s","params":%s}' "$method" "$params")"
    curl -sS --max-time "$RPC_TIMEOUT" \
        -H 'content-type: application/json' \
        --data "$payload" "$url" 2>/dev/null
}

rpc_result() { # url method params-json -> compact result JSON or empty
    local url="$1" method="$2" params="$3" resp
    resp="$(rpc_call "$url" "$method" "$params")" || return 1
    [[ -n "$resp" ]] || return 1
    printf '%s' "$resp" | jq -er 'if .error then empty else .result end' 2>/dev/null
}

height_of() { # url -> decimal height, non-zero exit if unreachable/bad
    local url="$1" hex digits
    hex="$(rpc_result "$url" stell_blockNumber '[]')" || return 1
    [[ "$hex" =~ ^0x[0-9a-fA-F]+$ ]] || return 1
    digits="${hex#0x}"
    # Reject values that cannot be represented as a non-negative shell integer.
    while [[ ${#digits} -gt 1 && "$digits" == 0* ]]; do digits="${digits#0}"; done
    (( ${#digits} <= 16 )) || return 1
    if (( ${#digits} == 16 )); then
        [[ "${digits:0:1}" =~ ^[0-7]$ ]] || return 1
    fi
    printf '%d' "$((16#$digits))"
}

hash_at() { # url height -> block hash or empty
    local url="$1" h="$2" result
    result="$(rpc_result "$url" stell_getBlock "[{\"height\":$h}]")" || return 1
    [[ -n "$result" && "$result" != "null" ]] || return 1
    printf '%s' "$result" | jq -er '.hash // empty' 2>/dev/null
}

health_json() { # health-url -> JSON or empty
    local base="$1"
    curl -sS --max-time "$RPC_TIMEOUT" "${base%/}/health" 2>/dev/null
}

# ---- polling ----------------------------------------------------------------
declare -A FIRST_H=() FIRST_T=() PREV_H=() LAST_H=() LAST_T=()
declare -A LAST_CHANGE=() LAST_REACH=() LAST_ERR=() HASH_AT=()
declare -A HAD_HEIGHT=()
HASH_MISMATCH=0
COMMON_HEIGHT=0

START_T="$(date +%s)"
TIP_LAST_CHANGE="$START_T"
TIP_SEEN=""

printf '%s: polling %d endpoint(s), interval %ss, window %ss, stall threshold %ss\n' \
    "$PROG" "${#NAMES[@]}" "$INTERVAL" "$WINDOW" "$STALL_SECS"
printf '%-4s %s\n' 't' 'height per node'

while :; do
    NOW="$(date +%s)"
    ELAPSED=$((NOW - START_T))
    LINE=""
    TIP=""

    for n in "${NAMES[@]}"; do
        if h="$(height_of "${RPC_URL[$n]}")"; then
            LAST_REACH["$n"]=1
            LAST_ERR["$n"]=""
            LAST_H["$n"]="$h"
            LAST_T["$n"]="$NOW"
            if [[ -z "${FIRST_H[$n]:-}" ]]; then
                FIRST_H["$n"]="$h"
                FIRST_T["$n"]="$NOW"
            fi
            if [[ -z "${PREV_H[$n]:-}" || "${PREV_H[$n]}" -ne "$h" ]]; then
                LAST_CHANGE["$n"]="$NOW"
            fi
            PREV_H["$n"]="$h"
            HAD_HEIGHT["$n"]=1
            LINE+=" $n=$h"
            if [[ -z "$TIP" || "$h" -gt "$TIP" ]]; then TIP="$h"; fi
        else
            LAST_REACH["$n"]=0
            LAST_ERR["$n"]="unreachable"
            LINE+=" $n=DOWN"
        fi
    done

    if [[ -n "$TIP" && "$TIP" != "$TIP_SEEN" ]]; then
        TIP_SEEN="$TIP"
        TIP_LAST_CHANGE="$NOW"
    fi

    SPREAD="-"
    if [[ -n "$TIP" ]]; then
        MIN=""
        for n in "${NAMES[@]}"; do
            [[ "${LAST_REACH[$n]:-0}" -eq 1 ]] || continue
            h="${LAST_H[$n]}"
            if [[ -z "$MIN" || "$h" -lt "$MIN" ]]; then MIN="$h"; fi
        done
        SPREAD=$((TIP - MIN))
    fi

    printf '[t=%3ss]%s  tip=%s spread=%s\n' "$ELAPSED" "$LINE" "${TIP:-none}" "$SPREAD"

    (( NOW - START_T >= WINDOW )) && break
    REM=$((WINDOW - (NOW - START_T)))
    SLEEP_FOR="$INTERVAL"
    (( SLEEP_FOR > REM )) && SLEEP_FOR="$REM"
    sleep "$SLEEP_FOR"
done

END_T="$(date +%s)"
ELAPSED=$((END_T - START_T))
(( ELAPSED > 0 )) || ELAPSED=1
STALLED_FOR=$((END_T - TIP_LAST_CHANGE))

# ---- final classification ---------------------------------------------------
REACHABLE=0
BACKWARD=0
MIN_H=""
MAX_H=""
for n in "${NAMES[@]}"; do
    if [[ "${LAST_REACH[$n]:-0}" -eq 1 ]]; then
        REACHABLE=$((REACHABLE + 1))
        h="${LAST_H[$n]}"
        if [[ -z "$MIN_H" || "$h" -lt "$MIN_H" ]]; then MIN_H="$h"; fi
        if [[ -z "$MAX_H" || "$h" -gt "$MAX_H" ]]; then MAX_H="$h"; fi
        if [[ -n "${FIRST_H[$n]:-}" && "$h" -lt "${FIRST_H[$n]}" ]]; then BACKWARD=1; fi
    fi
done

SPREAD=0
if [[ -n "$MIN_H" ]]; then SPREAD=$((MAX_H - MIN_H)); fi
COMMON_HEIGHT="$MIN_H"
if [[ -z "$COMMON_HEIGHT" ]]; then COMMON_HEIGHT=0; fi

# Compare the block hash at the highest common height. This catches a
# same-height execution fork that a height-only check would call "OK".
if (( COMMON_HEIGHT > 0 && REACHABLE >= 2 )); then
    declare -A HASHES=()
    for n in "${NAMES[@]}"; do
        [[ "${LAST_REACH[$n]:-0}" -eq 1 ]] || continue
        if hh="$(hash_at "${RPC_URL[$n]}" "$COMMON_HEIGHT")"; then
            [[ -n "$hh" ]] || continue
            HASH_AT["$n"]="$hh"
            HASHES["$hh"]=1
        fi
    done
    if (( ${#HASHES[@]} > 1 )); then HASH_MISMATCH=1; fi
    unset HASHES
fi

VERDICT="OK"
REASON=""
if (( REACHABLE == 0 )); then
    VERDICT="STALLED"
    REASON="all endpoints unreachable"
elif (( SPREAD > 1 )); then
    VERDICT="DIVERGED"
    REASON="height spread ${SPREAD} > 1"
elif (( BACKWARD )); then
    VERDICT="DIVERGED"
    REASON="a height regressed during the window"
elif (( HASH_MISMATCH )); then
    VERDICT="DIVERGED"
    REASON="block hash mismatch at common height ${COMMON_HEIGHT}"
elif [[ -n "$MIN_REACHABLE" ]] && (( REACHABLE < MIN_REACHABLE )); then
    VERDICT="STALLED"
    REASON="reachable endpoints ${REACHABLE} below minimum ${MIN_REACHABLE}"
elif (( STALLED_FOR > STALL_SECS )); then
    VERDICT="STALLED"
    REASON="cluster tip unchanged for ${STALLED_FOR}s > ${STALL_SECS}s"
fi

# ---- final table ------------------------------------------------------------
printf '\n'
printf '%-6s %-30s %10s %8s %14s %12s %s\n' \
    'NODE' 'ENDPOINT' 'HEIGHT' 'DELTA' 'FINALITY' 'LAST_CHANGE' 'STATUS'
for n in "${NAMES[@]}"; do
    endpoint="$(printf '%s' "${RPC_URL[$n]}" | redact_url)"
    if [[ "${LAST_REACH[$n]:-0}" -ne 1 ]]; then
        printf '%-6s %-30s %10s %8s %14s %12s %s\n' \
            "$n" "$endpoint" '-' '-' '-' '-' 'DOWN'
        continue
    fi
    h="${LAST_H[$n]}"
    if [[ -n "${FIRST_H[$n]:-}" ]]; then
        d=$((h - FIRST_H[$n]))
        secs=$((LAST_T[$n] - FIRST_T[$n]))
        (( secs > 0 )) || secs=1
        rate="$(awk -v d="$d" -v s="$secs" 'BEGIN { printf "%.2f", d * 60.0 / s }')"
        rate="${rate} blk/min"
    else
        d=0
        rate='-'
    fi
    last_change=$((END_T - ${LAST_CHANGE[$n]:-$START_T}))
    status="OK"
    if (( SPREAD > 1 )); then status="DIVERGED"
    elif (( BACKWARD )); then status="REGRESSED"
    elif (( STALLED_FOR > STALL_SECS )); then status="STALLED"
    fi
    printf '%-6s %-30s %10s %8s %14s %12s %s\n' \
        "$n" "$endpoint" "$h" "+${d}" "$rate" "${last_change}s" "$status"
done

printf '\ncluster: height=%s spread=%s reachable=%d/%d stalled_for=%ss\n' \
    "${MAX_H:-none}" "$SPREAD" "$REACHABLE" "${#NAMES[@]}" "$STALLED_FOR"

if [[ "$VERDICT" != "OK" ]]; then
    printf 'verdict: %s (%s)\n' "$VERDICT" "$REASON"
else
    printf 'verdict: OK\n'
fi

# ---- diagnostics on failure -------------------------------------------------
if [[ "$VERDICT" != "OK" ]]; then
    printf '\n===== DIAGNOSTICS =====\n'
    for n in "${NAMES[@]}"; do
        printf '\n---- %s  %s ----\n' "$n" "$(printf '%s' "${RPC_URL[$n]}" | redact_url)"

        if [[ "${LAST_REACH[$n]:-0}" -eq 1 ]]; then
            printf 'rpc: reachable, stell_blockNumber=%s\n' "${LAST_H[$n]}"
        else
            printf 'rpc: UNREACHABLE (%s)\n' "${LAST_ERR[$n]:-error}"
        fi

        hbase="${HEALTH_URL[$n]:-}"
        if [[ -n "$hbase" ]]; then
            hjson="$(health_json "$hbase")"
            if [[ -n "$hjson" ]] && printf '%s' "$hjson" | jq -e . >/dev/null 2>&1; then
                printf 'health: %s/health ->\n' "${hbase%/}" | redact_url
                printf '%s' "$hjson" | jq -r '
                    def v: if . == null then "null" else tostring end;
                    "  verdict=\(.verdict.status // "unknown")",
                    "  height=\(.chain.height.value? | v) finalized_height=\(.chain.finalized_height.value? | v)",
                    "  round=\(.consensus.round.value? | v) last_finalized_round=\(.consensus.last_finalized_round.value? | v)",
                    "  peers=\(.p2p.peer_count.value? | v) rejected_proposals_total=\(.consensus.rejected_proposals_total.value? | v)",
                    "  chain_id=\(.identity.chain_id? | v) fork_id=\(.identity.fork_id? | v)",
                    "  software=\(.identity.software.string? // "unknown")"
                ' 2>/dev/null
                printf '%s' "$hjson" | jq -r '.verdict.reasons[]? | "  reason: " + .' 2>/dev/null
                printf '%s' "$hjson" | jq -r '.verdict.unknown[]? | "  unknown: " + .' 2>/dev/null
            else
                printf 'health: unavailable (GET %s/health failed or returned non-JSON)\n' "${hbase%/}" | redact_url
                # Fall back to the two fields the RPC can still answer.
                pc="$(rpc_result "${RPC_URL[$n]}" net_peerCount '[]' 2>/dev/null || true)"
                if [[ "$pc" =~ ^0x[0-9a-fA-F]+$ ]]; then
                    printf '  peers(net_peerCount)=%d\n' "$((16#${pc#0x}))"
                fi
                printf '  round: not exposed without /health\n'
                printf '  finalized_height(RPC height)=%s\n' "${LAST_H[$n]:-unknown}"
            fi
        else
            printf 'health: not configured\n'
        fi

        if [[ "$COMMON_HEIGHT" -gt 0 ]]; then
            printf 'hash@%s=%s\n' "$COMMON_HEIGHT" "${HASH_AT[$n]:-unavailable}"
        fi

        jcmd="${JOURNAL_CMD[$n]:-$JOURNAL_GLOBAL}"
        if [[ -n "$jcmd" ]]; then
            printf 'journal: last %d rejected-proposal reasons via: %s\n' \
                "$JOURNAL_LAST" "$(printf '%s' "$jcmd" | redact_line)"
            if [[ "$jcmd" == *journalctl* ]]; then
                full="$jcmd --no-pager -n $JOURNAL_SCAN"
            else
                full="$jcmd 2>/dev/null | tail -n $JOURNAL_SCAN"
            fi
            reasons="$(timeout 30 bash -c "$full" 2>/dev/null \
                | grep -iE 'rejected proposal|proposal[^a-z]+reject|reject(ed)?[^a-z]+proposal' \
                | tail -n "$JOURNAL_LAST" \
                | redact_line || true)"
            if [[ -n "$reasons" ]]; then
                printf '%s\n' "$reasons" | sed 's/^/  /'
            else
                printf '  (no rejected-proposal lines found)\n'
            fi
        else
            printf 'journal: not supplied (--journal)\n'
        fi
    done
fi

# ---- machine-readable line --------------------------------------------------
MACHINE_REASON="${REASON:-none}"
MACHINE_REASON="${MACHINE_REASON// /_}"
printf 'LIVENESS_RESULT=%s height=%s spread=%s reachable=%d/%d stalled_for=%ss window=%ss stall_threshold=%ss reason=%s\n' \
    "$VERDICT" "${MAX_H:-none}" "$SPREAD" "$REACHABLE" "${#NAMES[@]}" \
    "$STALLED_FOR" "$WINDOW" "$STALL_SECS" "$MACHINE_REASON"

case "$VERDICT" in
    OK)       exit 0 ;;
    STALLED)  exit 1 ;;
    DIVERGED) exit 2 ;;
    *)        exit 1 ;;
esac
