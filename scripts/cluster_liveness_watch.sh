#!/usr/bin/env bash
# ==============================================================================
# cluster_liveness_watch.sh — periodic, read-only liveness probe + Prometheus
# textfile for node_exporter's textfile collector.
#
# It runs scripts/cluster_liveness.sh on a fixed cadence, appends only the
# machine-readable LIVENESS_RESULT= line to a log, and atomically rewrites a
# textfile with four gauges:
#
#   stell_cluster_liveness_ok 1        verdict OK
#                             0        STALLED / DIVERGED / runner error
#   stell_cluster_height      highest observed height (0 if unreachable)
#   stell_cluster_spread      max(height) - min(height) among reachable nodes
#   stell_cluster_stalled_seconds  seconds since the cluster tip last advanced
#
# Alert on `stell_cluster_liveness_ok == 0` and `stell_cluster_spread > 1`;
# rules live in ops/alert_rules.yaml.
#
# SAFETY: this wrapper only reads the cluster (via cluster_liveness.sh) and
# writes exactly two operator-named paths: --log and --textfile. It never
# restarts, prunes, clears a lock or touches a node data directory.
#
# Install the textfile under the node_exporter collector directory, e.g.
#
#   scripts/cluster_liveness_watch.sh \
#     --rpcs "A=http://127.0.0.1:8545,B=http://127.0.0.1:8546" \
#     --log /var/log/stell/cluster-liveness.log \
#     --textfile /var/lib/node_exporter/textfile_collector/stell_cluster_liveness.prom
#
# node_exporter is then started with
#   --collector.textfile.directory=/var/lib/node_exporter/textfile_collector
#
# Exit codes:
#   0   continuous loop ended by a signal, or --once with an OK verdict
#   1   usage/config error, or --once with STALLED / runner error
#   2   --once with a DIVERGED verdict
#   64  usage/config error (same convention as cluster_liveness.sh)
# ==============================================================================
set -uo pipefail

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIVENESS_BIN="${STELL_LIVENESS_BIN:-$SCRIPT_DIR/cluster_liveness.sh}"

WATCH_INTERVAL="${STELL_LIVENESS_WATCH_INTERVAL:-60}"
LOG_FILE="${STELL_LIVENESS_LOG:-/tmp/stell_cluster_liveness.log}"
TEXTFILE="${STELL_LIVENESS_TEXTFILE:-/tmp/stell_cluster_liveness.prom}"
ONCE=0
QUIET=0
declare -a LIVENESS_ARGS=()

usage() {
    cat <<EOF
$PROG — run cluster_liveness.sh every N seconds and export textfile metrics

USAGE
  STELL_RPCS="A=http://127.0.0.1:8545,B=http://127.0.0.1:8546" $PROG [options]
  $PROG --rpcs "A=...,B=..." [options]

OPTIONS
  --watch-interval SEC   seconds between probe starts (default $WATCH_INTERVAL)
  --log FILE             append LIVENESS_RESULT= lines here
                         (default $LOG_FILE)
  --textfile FILE        Prometheus textfile to rewrite atomically
                         (default $TEXTFILE)
  --once                 run one probe, write the files, exit with the verdict
  --quiet                do not echo each LIVENESS_RESULT= line
  --help                 this text

  Everything else (--rpcs, --health-rpcs, --window, --timeout, --journal,
  --expected-block-time, --stall-factor, --interval, ...) is forwarded
  verbatim to scripts/cluster_liveness.sh.

  Note: --interval is the INNER polling interval of cluster_liveness.sh;
  use --watch-interval for the wrapper's cadence. A probe blocks for
  cluster_liveness.sh's --window (default 60s), so with both defaults the
  wrapper probes back-to-back.

METRICS
  stell_cluster_liveness_ok
  stell_cluster_height
  stell_cluster_spread
  stell_cluster_stalled_seconds

COLLECTOR
  Point node_exporter at the textfile directory:
    node_exporter --collector.textfile.directory=/var/lib/node_exporter/textfile_collector

EXAMPLES
  # one probe against two local endpoints
  $PROG --once --rpcs "A=http://127.0.0.1:8545,B=http://127.0.0.1:8546"

  # one probe with a fake/unreachable endpoint (safe smoke test)
  $PROG --once --timeout 1 --window 1 --rpcs "A=http://127.0.0.1:1"

  # continuous, 60s cadence, production paths
  $PROG --watch-interval 60 \\
    --rpcs "A=http://127.0.0.1:8545,B=http://127.0.0.1:8546" \\
    --log /var/log/stell/cluster-liveness.log \\
    --textfile /var/lib/node_exporter/textfile_collector/stell_cluster_liveness.prom
EOF
}

die() {
    printf '%s: %s\n' "$PROG" "$*" >&2
    exit 64
}

need_value() {
    [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
}

warn() {
    printf '%s: %s\n' "$PROG" "$*" >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --watch-interval) need_value "$@"; WATCH_INTERVAL="$2"; shift 2 ;;
        --log)            need_value "$@"; LOG_FILE="$2"; shift 2 ;;
        --textfile)       need_value "$@"; TEXTFILE="$2"; shift 2 ;;
        --once)           ONCE=1; shift ;;
        --quiet)          QUIET=1; shift ;;
        --help|-h)        usage; exit 0 ;;
        *)                LIVENESS_ARGS+=("$1"); shift ;;
    esac
done

[[ "$WATCH_INTERVAL" =~ ^[1-9][0-9]*$ ]] || die "--watch-interval must be a positive integer"
[[ -f "$LIVENESS_BIN" ]] || die "liveness script not found: $LIVENESS_BIN"
[[ -n "$LOG_FILE" ]] || die "--log must not be empty"
[[ -n "$TEXTFILE" ]] || die "--textfile must not be empty"

# ---- helpers -----------------------------------------------------------------
field() { # line key -> value (first match), empty when absent
    printf '%s\n' "$1" | sed -n "s/.*[[:space:]]$2=\([^[:space:]]*\).*/\1/p" | head -n 1
}

num_or_zero() {
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        printf '%s' "$1"
    else
        printf '0'
    fi
}

write_metrics() { # ok height spread stalled_seconds
    local ok="$1" height="$2" spread="$3" stalled="$4"
    local tmp="${TEXTFILE}.tmp.$$"
    {
        printf '# HELP stell_cluster_liveness_ok 1 when cluster_liveness.sh verdict is OK, else 0\n'
        printf '# TYPE stell_cluster_liveness_ok gauge\n'
        printf 'stell_cluster_liveness_ok %s\n' "$ok"
        printf '# HELP stell_cluster_height Highest stell_blockNumber observed across reachable nodes\n'
        printf '# TYPE stell_cluster_height gauge\n'
        printf 'stell_cluster_height %s\n' "$height"
        printf '# HELP stell_cluster_spread Max minus min height across reachable nodes\n'
        printf '# TYPE stell_cluster_spread gauge\n'
        printf 'stell_cluster_spread %s\n' "$spread"
        printf '# HELP stell_cluster_stalled_seconds Seconds since the cluster tip last advanced\n'
        printf '# TYPE stell_cluster_stalled_seconds gauge\n'
        printf 'stell_cluster_stalled_seconds %s\n' "$stalled"
    } > "$tmp" || {
        rm -f "$tmp"
        return 1
    }
    mv -f "$tmp" "$TEXTFILE" || {
        rm -f "$tmp"
        return 1
    }
}

# ---- one probe ---------------------------------------------------------------
probe() {
    local output rc result_line ts height_raw spread_raw stalled_raw
    local ok height spread stalled verdict_rc=0

    rc=0
    output="$(bash "$LIVENESS_BIN" "${LIVENESS_ARGS[@]}" 2>&1)" || rc=$?
    result_line="$(printf '%s\n' "$output" | grep -m1 '^LIVENESS_RESULT=' || true)"

    if [[ -z "$result_line" ]]; then
        # The liveness script failed before printing its machine line (usage
        # error, missing curl/jq, ...). Keep the log shape stable and emit a
        # failing sample rather than leaving the last good value in place.
        result_line="LIVENESS_RESULT=ERROR height=0 spread=0 reachable=0/0 stalled_for=0s reason=runner_error_rc_${rc}"
        printf '%s\n' "$output" >&2
        warn "no LIVENESS_RESULT line (rc=$rc); wrote a failing sample"
    fi

    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # Keep the line machine-parseable: it still starts with LIVENESS_RESULT=.
    if ! printf '%s ts=%s\n' "$result_line" "$ts" >> "$LOG_FILE"; then
        warn "cannot append to log: $LOG_FILE"
    fi
    [[ "$QUIET" -eq 1 ]] || printf '%s\n' "$result_line"

    height_raw="$(field "$result_line" height)"
    spread_raw="$(field "$result_line" spread)"
    stalled_raw="$(field "$result_line" stalled_for)"
    stalled_raw="${stalled_raw%s}"

    height="$(num_or_zero "$height_raw")"
    spread="$(num_or_zero "$spread_raw")"
    stalled="$(num_or_zero "$stalled_raw")"

    ok=0
    case "$result_line" in
        LIVENESS_RESULT=OK\ *) ok=1 ;;
    esac
    (( rc == 0 )) || ok=0

    if ! write_metrics "$ok" "$height" "$spread" "$stalled"; then
        warn "cannot write textfile: $TEXTFILE"
        return 1
    fi

    if (( ok == 1 )); then
        verdict_rc=0
    else
        case "$result_line" in
            LIVENESS_RESULT=DIVERGED\ *) verdict_rc=2 ;;
            *)                           verdict_rc=1 ;;
        esac
    fi
    return "$verdict_rc"
}

# ---- loop --------------------------------------------------------------------
RUNNING=1
trap 'RUNNING=0' INT TERM

while (( RUNNING == 1 )); do
    started="$(date +%s)"
    probe
    probe_rc=$?

    if (( ONCE == 1 )); then
        exit "$probe_rc"
    fi

    now="$(date +%s)"
    delay=$(( WATCH_INTERVAL - (now - started) ))
    (( delay < 1 )) && delay=1
    # Sleep in 1 s slices so SIGTERM stops the watcher promptly instead of
    # waiting out a 60 s sleep.
    for (( i = 0; i < delay; i++ )); do
        (( RUNNING == 1 )) || break
        sleep 1
    done
done

exit 0
