#!/usr/bin/env bash
# ==============================================================================
# cluster_liveness_watch.sh — periodic, read-only liveness probe + Prometheus
# textfile for node_exporter's textfile collector.
#
# It runs scripts/cluster_liveness.sh on a fixed cadence, appends only the
# machine-readable LIVENESS_RESULT= line to a log, and atomically rewrites a
# textfile with the liveness gauges plus per-node tick and clock health:
#
#   stell_cluster_liveness_ok 1        verdict OK
#                             0        STALLED / DIVERGED / runner error
#   stell_cluster_height      highest observed height (0 if unreachable)
#   stell_cluster_spread      max(height) - min(height) among reachable nodes
#   stell_cluster_stalled_seconds  seconds since the cluster tip last advanced
#
#   stell_tick_p50_ms{node}       median duration of logged `[perf] tick` lines
#   stell_tick_p99_ms{node}       99th percentile of the same sample
#   stell_tick_over_1s_ratio{node} fraction of that sample above 1000 ms
#   stell_tick_samples{node}      number of tick lines in the bounded window
#   stell_clock_skew_ms{node}     node clock minus watcher clock (positive = ahead)
#   stell_clock_sync_ok{node}     1 unless |skew| > 1000 ms or NTP is off/unknown
#
# The tick sample comes from the node journal over a bounded time window
# (--tick-window, default 900 s). The node only logs a `[perf] tick` line when
# the tick takes >= 400 ms, so these are statistics of SLOW ticks, not of every
# tick: `stell_tick_over_1s_ratio` is a fraction of logged ticks. Read
# `stell_tick_samples` alongside the percentiles; zero samples means the journal
# command returned nothing, not a healthy node.
#
# READ-ONLY. The journal/clock commands are operator-supplied and may cross ssh,
# but this script never writes anything except --log and --textfile.
#
# Alert on `stell_cluster_liveness_ok == 0`, `stell_cluster_spread > 1`,
# `stell_tick_p99_ms > 2000`, `stell_tick_over_1s_ratio > 0.2`, and
# `stell_clock_sync_ok == 0`; rules live in ops/alert_rules.yaml.
#
# SAFETY: this wrapper only reads the cluster (via cluster_liveness.sh and the
# journal/clock commands) and writes exactly two operator-named paths: --log
# and --textfile. It never restarts, prunes, clears a lock or touches a node
# data directory.
#
# Install the textfile under the node_exporter collector directory, e.g.
#
#   scripts/cluster_liveness_watch.sh \
#     --rpcs "A=http://127.0.0.1:8545,B=http://127.0.0.1:8546" \
#     --journal "A=ssh root@hostA journalctl -u stell-nodeA" \
#     --journal "B=journalctl --user -u stell-nodeB" \
#     --clock "A=ssh root@hostA 'timedatectl show -p NTPSynchronized --value; date +%s%3N'" \
#     --clock "B=timedatectl show -p NTPSynchronized --value; date +%s%3N" \
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
DEFAULT_LIVENESS_STATE_DIR="${XDG_RUNTIME_DIR:-$HOME/.local/state}/stellereum-liveness"
LOG_FILE="${STELL_LIVENESS_LOG:-$DEFAULT_LIVENESS_STATE_DIR/cluster_liveness.log}"
TEXTFILE="${STELL_LIVENESS_TEXTFILE:-$DEFAULT_LIVENESS_STATE_DIR/cluster_liveness.prom}"

# Tick/clock sampling. The journal window is bounded by time for journalctl
# commands and by line count for anything else (ssh, cat, a test fixture).
TICK_WINDOW="${STELL_LIVENESS_TICK_WINDOW:-900}"
TICK_LINES="${STELL_LIVENESS_TICK_LINES:-20000}"
TICK_TIMEOUT="${STELL_LIVENESS_TICK_TIMEOUT:-20}"
CLOCK_TIMEOUT="${STELL_LIVENESS_CLOCK_TIMEOUT:-10}"
CLOCK_DEFAULT='timedatectl show -p NTPSynchronized --value; date +%s%3N'

ONCE=0
QUIET=0
declare -a LIVENESS_ARGS=()
declare -a NODE_NAMES=()
declare -A NODE_SEEN=()
declare -A JOURNAL_CMD=()
declare -A CLOCK_CMD=()
JOURNAL_GLOBAL=""
CLOCK_GLOBAL=""

# Filled once per probe; arrays are keyed by node name.
declare -A TICK_P50=() TICK_P99=() TICK_RATIO=() TICK_SAMPLES=()
declare -A CLOCK_SKEW=() CLOCK_OK=() CLOCK_NTP=()

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
  --journal CMD          journal command used for \`[perf] tick\` parsing.
                         Repeatable: "A=ssh root@host journalctl -u stell-nodeA".
                         A bare value applies to every node. Default per node:
                         "journalctl --no-pager -u stell-node<NAME>".
                         The same value is forwarded to cluster_liveness.sh.
  --tick-window SEC      bounded journal window for tick statistics
                         (default $TICK_WINDOW). journalctl commands get
                         \`--since=-<window>\`; other commands are line-capped.
  --tick-lines N         maximum journal lines read per node (default $TICK_LINES)
  --tick-timeout SEC     per-node journal command timeout (default $TICK_TIMEOUT)
  --clock CMD            command that prints NTPSynchronized=yes|no and/or an
                         epoch-milliseconds line, run ON the node. Repeatable:
                         "A=ssh root@host 'timedatectl show -p NTPSynchronized
                         --value; date +%s%3N'". A bare value applies to every
                         node. Default (the watcher's local host):
                         "$CLOCK_DEFAULT"
                         For remote nodes supply --clock per node; the default
                         measures the host running the watcher, not the node.
  --clock-timeout SEC    per-node clock command timeout (default $CLOCK_TIMEOUT)
  --min-reachable N      forward minimum final-poll RPC heights to the probe
                         (default 1; not a validator or P2P quorum)
  --once                 run one probe, write the files, exit with the verdict
  --quiet                do not echo each LIVENESS_RESULT= line
  --help                 this text

  Everything else (--rpcs, --health-rpcs, --window, --timeout,
  --expected-block-time, --stall-factor, --interval, --journal-last, ...) is
  forwarded verbatim to scripts/cluster_liveness.sh.

  OK permits partial reachability by default and does not prove hash agreement:
  missing hash responses do not fail the probe. Check the log's reachable=N/M.

  Note: --interval is the INNER polling interval of cluster_liveness.sh;
  use --watch-interval for the wrapper's cadence. A probe blocks for
  cluster_liveness.sh's --window (default 60s), so with both defaults the
  wrapper probes back-to-back.

METRICS
  stell_cluster_liveness_ok
  stell_cluster_height
  stell_cluster_spread
  stell_cluster_stalled_seconds
  stell_tick_p50_ms{node}
  stell_tick_p99_ms{node}
  stell_tick_over_1s_ratio{node}
  stell_tick_samples{node}
  stell_clock_skew_ms{node}
  stell_clock_sync_ok{node}

COLLECTOR
  Point node_exporter at the textfile directory:
    node_exporter --collector.textfile.directory=/var/lib/node_exporter/textfile_collector

EXAMPLES
  # one probe against two local endpoints
  $PROG --once --rpcs "A=http://127.0.0.1:8545,B=http://127.0.0.1:8546"

  # one probe with a fake/unreachable endpoint (safe smoke test)
  $PROG --once --timeout 1 --window 1 --rpcs "A=http://127.0.0.1:1"

  # one probe with explicit per-node journals and clocks
  $PROG --once --timeout 1 --window 1 --rpcs "A=http://127.0.0.1:1" \\
    --journal "A=journalctl -u stell-nodeA" \\
    --clock "A=timedatectl show -p NTPSynchronized --value; date +%s%3N"

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

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --watch-interval) need_value "$@"; WATCH_INTERVAL="$2"; shift 2 ;;
        --log)            need_value "$@"; LOG_FILE="$2"; shift 2 ;;
        --textfile)       need_value "$@"; TEXTFILE="$2"; shift 2 ;;
        --journal)
            need_value "$@"
            if [[ "$2" =~ ^[A-Za-z0-9_.-]+= ]]; then
                JOURNAL_CMD["${2%%=*}"]="${2#*=}"
            else
                JOURNAL_GLOBAL="$2"
            fi
            # Keep cluster_liveness.sh's rejected-proposal diagnostics intact.
            LIVENESS_ARGS+=("--journal" "$2")
            shift 2 ;;
        --clock)
            need_value "$@"
            if [[ "$2" =~ ^[A-Za-z0-9_.-]+= ]]; then
                CLOCK_CMD["${2%%=*}"]="${2#*=}"
            else
                CLOCK_GLOBAL="$2"
            fi
            shift 2 ;;
        --tick-window)    need_value "$@"; TICK_WINDOW="$2"; shift 2 ;;
        --tick-lines)     need_value "$@"; TICK_LINES="$2"; shift 2 ;;
        --tick-timeout)   need_value "$@"; TICK_TIMEOUT="$2"; shift 2 ;;
        --clock-timeout)  need_value "$@"; CLOCK_TIMEOUT="$2"; shift 2 ;;
        --min-reachable)  need_value "$@"; LIVENESS_ARGS+=("$1" "$2"); shift 2 ;;
        --once)           ONCE=1; shift ;;
        --quiet)          QUIET=1; shift ;;
        --help|-h)        usage; exit 0 ;;
        *)                LIVENESS_ARGS+=("$1"); shift ;;
    esac
done

[[ "$WATCH_INTERVAL" =~ ^[1-9][0-9]*$ ]] || die "--watch-interval must be a positive integer"
[[ "$TICK_WINDOW"   =~ ^[1-9][0-9]*$ ]] || die "--tick-window must be a positive integer"
[[ "$TICK_LINES"    =~ ^[1-9][0-9]*$ ]] || die "--tick-lines must be a positive integer"
[[ "$TICK_TIMEOUT"  =~ ^[1-9][0-9]*$ ]] || die "--tick-timeout must be a positive integer"
[[ "$CLOCK_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "--clock-timeout must be a positive integer"
[[ -f "$LIVENESS_BIN" ]] || die "liveness script not found: $LIVENESS_BIN"
[[ -n "$LOG_FILE" ]] || die "--log must not be empty"
[[ -n "$TEXTFILE" ]] || die "--textfile must not be empty"
mkdir -p -m 0700 "$(dirname "$LOG_FILE")" "$(dirname "$TEXTFILE")" 2>/dev/null || true
chmod 0700 "$DEFAULT_LIVENESS_STATE_DIR" 2>/dev/null || true

# ---- node names --------------------------------------------------------------
# Derive the node labels from the same --rpcs / STELL_RPCS value that
# cluster_liveness.sh consumes. Only the part before '=' is a name; attributes
# such as ';health=...' stay attached to the URL.
parse_nodes() {
    local spec="" entry name i arg nxt
    local -a entries

    for (( i = 0; i < ${#LIVENESS_ARGS[@]}; i++ )); do
        arg="${LIVENESS_ARGS[$i]}"
        if [[ "$arg" == "--rpcs" ]]; then
            nxt=$((i + 1))
            if (( nxt < ${#LIVENESS_ARGS[@]} )); then spec="${LIVENESS_ARGS[$nxt]}"; fi
        elif [[ "$arg" == --rpcs=* ]]; then
            spec="${arg#--rpcs=}"
        fi
    done
    [[ -n "$spec" ]] || spec="${STELL_RPCS:-}"

    IFS=',' read -r -a entries <<< "$spec"
    for entry in "${entries[@]}"; do
        entry="$(trim "$entry")"
        [[ -n "$entry" && "$entry" == *=* ]] || continue
        name="$(trim "${entry%%=*}")"
        [[ -n "$name" ]] || continue
        [[ -z "${NODE_SEEN[$name]:-}" ]] || continue
        NODE_SEEN["$name"]=1
        NODE_NAMES+=("$name")
    done
}

parse_nodes

for name in "${!JOURNAL_CMD[@]}"; do
    [[ -n "${NODE_SEEN[$name]:-}" ]] || die "--journal names an unknown node: $name"
done
for name in "${!CLOCK_CMD[@]}"; do
    [[ -n "${NODE_SEEN[$name]:-}" ]] || die "--clock names an unknown node: $name"
done

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

label_value() { # escape a Prometheus label value
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# Full journal command for tick parsing. journalctl gets a bounded time window;
# anything else (ssh, cat, a fixture) is capped by line count.
tick_command() { # node command -> shell command on stdout
    local cmd="$1" since_min
    if [[ "$cmd" == *journalctl* && "$cmd" != *'|'* ]]; then
        since_min=$(( (TICK_WINDOW + 59) / 60 ))
        printf '%s --no-pager -o cat --since=-%dmin -n %d' \
            "$cmd" "$since_min" "$TICK_LINES"
    else
        printf '%s 2>/dev/null | tail -n %d' "$cmd" "$TICK_LINES"
    fi
}

# `[perf] tick h=... took 2.577s (catchup=... flushes=3 ...)` -> one ms value
# per line. Rust's Duration Debug format yields ns / us / ms / s suffixes.
tick_samples_ms() { # node command
    local cmd="$1" full
    full="$(tick_command "$cmd")"
    timeout "$TICK_TIMEOUT" bash -c "$full" 2>/dev/null \
        | sed -nE 's/.*\[perf\] tick .* took ([0-9]+(\.[0-9]+)?)([^[:space:]]+).*/\1 \3/p' \
        | awk '
            NF >= 2 {
                v = $1 + 0
                u = $2
                if (u == "ns")                 ms = v / 1000000.0
                else if (u == "us" || u == "\302\265s" || u == "\316\274s") ms = v / 1000.0
                else if (u == "ms")            ms = v
                else if (u == "s")             ms = v * 1000.0
                else                           next
                printf "%.3f\n", ms
            }'
}

# -> "p50_ms p99_ms over_1s_ratio samples" (all zeros when nothing parsed).
tick_stats() { # node command
    local values n i50 i99 p50 p99 over
    values="$(tick_samples_ms "$1" | sort -n)"
    n="$(printf '%s\n' "$values" | awk 'NF { n++ } END { print n + 0 }')"
    if (( n == 0 )); then
        printf '0 0 0 0'
        return 0
    fi
    # Nearest-rank percentiles: p50 = ceil(0.50*n), p99 = ceil(0.99*n).
    i50=$(( (n * 50 + 99) / 100 ))
    i99=$(( (n * 99 + 99) / 100 ))
    p50="$(printf '%s\n' "$values" | sed -n "${i50}p")"
    p99="$(printf '%s\n' "$values" | sed -n "${i99}p")"
    over="$(printf '%s\n' "$values" | awk '$1 > 1000 { c++ } END { print c + 0 }')"
    awk -v p50="$p50" -v p99="$p99" -v over="$over" -v n="$n" \
        'BEGIN { printf "%.1f %.1f %.4f %d\n", p50, p99, over / n, n }'
}

# -> "skew_ms ntp" where skew_ms is a number or "NaN", ntp is yes|no|unknown.
# The optional epoch-milliseconds line is compared with the midpoint of the
# local clock around the command, which cancels most of the command RTT.
clock_measure() { # node command
    local cmd="$1" before after out node_ms ntp skew
    before="$(date +%s%3N)"
    out="$(timeout "$CLOCK_TIMEOUT" bash -c "$cmd" 2>/dev/null)" || out=""
    after="$(date +%s%3N)"

    ntp="$(printf '%s\n' "$out" \
        | sed -nE 's/.*Synchronized=(yes|no).*/\1/p' \
        | tail -n 1)"
    if [[ -z "$ntp" ]]; then
        ntp="$(printf '%s\n' "$out" \
            | awk 'tolower($0) ~ /^(yes|no)$/ { v = tolower($0) } END { if (v != "") print v }')"
    fi
    [[ -n "$ntp" ]] || ntp="unknown"

    # Epoch milliseconds are 12+ digits today; shorter numbers are ignored so
    # an unrelated counter in the command output cannot be mistaken for a clock.
    node_ms="$(printf '%s\n' "$out" \
        | awk '/^[0-9]+$/ && length($0) >= 12 { v = $0 } END { if (v != "") print v }')"

    if [[ -n "$node_ms" ]]; then
        skew="$(awk -v n="$node_ms" -v a="$before" -v b="$after" \
            'BEGIN { printf "%.1f", n - (a + b) / 2.0 }')"
    else
        skew="NaN"
    fi
    printf '%s %s' "$skew" "$ntp"
}

clock_ok() { # skew ntp -> 1|0
    local skew="$1" ntp="$2" bad
    if [[ "$skew" != "NaN" ]]; then
        bad="$(awk -v s="$skew" 'BEGIN { s = (s < 0 ? -s : s); print (s > 1000 ? 1 : 0) }')"
        if (( bad == 1 )); then
            printf '0'
            return
        fi
        # A measurable, in-range clock still reports 0 when NTP is explicitly
        # disabled: the clock can be right now and drift away next hour.
        if [[ "$ntp" == "no" ]]; then
            printf '0'
        else
            printf '1'
        fi
        return
    fi
    # No timestamp handshake: trust an explicit NTP yes, fail closed otherwise.
    if [[ "$ntp" == "yes" ]]; then printf '1'; else printf '0'; fi
}

collect_tick_clock() {
    local n jcmd ccmd p50 p99 ratio samples skew ntp ok
    for n in "${NODE_NAMES[@]}"; do
        jcmd="${JOURNAL_CMD[$n]:-$JOURNAL_GLOBAL}"
        [[ -n "$jcmd" ]] || jcmd="journalctl --no-pager -u stell-node${n}"
        read -r p50 p99 ratio samples <<< "$(tick_stats "$jcmd")"
        TICK_P50["$n"]="$p50"
        TICK_P99["$n"]="$p99"
        TICK_RATIO["$n"]="$ratio"
        TICK_SAMPLES["$n"]="$samples"

        ccmd="${CLOCK_CMD[$n]:-$CLOCK_GLOBAL}"
        [[ -n "$ccmd" ]] || ccmd="$CLOCK_DEFAULT"
        read -r skew ntp <<< "$(clock_measure "$ccmd")"
        ok="$(clock_ok "$skew" "$ntp")"
        CLOCK_SKEW["$n"]="$skew"
        CLOCK_NTP["$n"]="$ntp"
        CLOCK_OK["$n"]="$ok"
    done
}

write_metrics() { # ok height spread stalled_seconds
    local ok="$1" height="$2" spread="$3" stalled="$4" n lbl tmp
    tmp="$(mktemp "${TEXTFILE}.tmp.XXXXXX")" || return 1
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

        printf '# HELP stell_tick_p50_ms Median duration of logged [perf] tick lines in the bounded journal window\n'
        printf '# TYPE stell_tick_p50_ms gauge\n'
        for n in "${NODE_NAMES[@]}"; do
            lbl="$(label_value "$n")"
            printf 'stell_tick_p50_ms{node="%s"} %s\n' "$lbl" "${TICK_P50[$n]:-0}"
        done

        printf '# HELP stell_tick_p99_ms 99th percentile of logged [perf] tick durations in the bounded journal window\n'
        printf '# TYPE stell_tick_p99_ms gauge\n'
        for n in "${NODE_NAMES[@]}"; do
            lbl="$(label_value "$n")"
            printf 'stell_tick_p99_ms{node="%s"} %s\n' "$lbl" "${TICK_P99[$n]:-0}"
        done

        printf '# HELP stell_tick_over_1s_ratio Fraction of logged tick lines above 1000 ms (logged ticks only)\n'
        printf '# TYPE stell_tick_over_1s_ratio gauge\n'
        for n in "${NODE_NAMES[@]}"; do
            lbl="$(label_value "$n")"
            printf 'stell_tick_over_1s_ratio{node="%s"} %s\n' "$lbl" "${TICK_RATIO[$n]:-0}"
        done

        printf '# HELP stell_tick_samples Number of [perf] tick lines parsed from the node journal (0 = journal command returned nothing)\n'
        printf '# TYPE stell_tick_samples gauge\n'
        for n in "${NODE_NAMES[@]}"; do
            lbl="$(label_value "$n")"
            printf 'stell_tick_samples{node="%s"} %s\n' "$lbl" "${TICK_SAMPLES[$n]:-0}"
        done

        printf '# HELP stell_clock_skew_ms Node clock minus watcher clock at probe time (positive = node ahead); NaN when no timestamp handshake\n'
        printf '# TYPE stell_clock_skew_ms gauge\n'
        for n in "${NODE_NAMES[@]}"; do
            lbl="$(label_value "$n")"
            printf 'stell_clock_skew_ms{node="%s"} %s\n' "$lbl" "${CLOCK_SKEW[$n]:-NaN}"
        done

        printf '# HELP stell_clock_sync_ok 1 when clock skew is within 1000 ms and NTP is not explicitly off, else 0\n'
        printf '# TYPE stell_clock_sync_ok gauge\n'
        for n in "${NODE_NAMES[@]}"; do
            lbl="$(label_value "$n")"
            printf 'stell_clock_sync_ok{node="%s"} %s\n' "$lbl" "${CLOCK_OK[$n]:-0}"
        done
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

    # Independent of the liveness verdict: a stalled cluster still has tick and
    # clock health worth exporting.
    collect_tick_clock

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
