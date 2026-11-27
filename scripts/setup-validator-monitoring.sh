#!/usr/bin/env bash
# ==============================================================================
# setup-validator-monitoring.sh — Idempotently install/verify
# prometheus-node-exporter (strictly bound to 127.0.0.1:9100) on remote
# validators A/C/D and manage SSH local forwards for Prometheus.
#
# WHY LOOPBACK + SSH TUNNELS:
#   Exposing :9100 to the internet leaks host inventory and lets unauthenticated
#   scanners scrape node metrics. Each remote validator binds
#   prometheus-node-exporter strictly to 127.0.0.1:9100, and this script opens
#   local SSH forwards on the monitoring host:
#
#     A  127.0.0.1:9102 -> NODE_A_SSH -> 127.0.0.1:9100
#     C  127.0.0.1:9103 -> NODE_C_SSH -> 127.0.0.1:9100
#     D  127.0.0.1:9104 -> NODE_D_SSH -> 127.0.0.1:9100
#
#   (Validator B runs on the build/monitoring host and is already scraped by
#   ops/observability/prometheus.yml job `node` at 127.0.0.1:9101.)
#
# Usage:
#   scripts/setup-validator-monitoring.sh [COMMAND] [OPTIONS]
#
# Commands:
#   setup           Install/verify remote node_exporter + start SSH tunnels (default)
#   start           Alias for setup (or start tunnels only with --tunnels-only)
#   stop            Stop managed SSH local forwards
#   restart         Stop and re-start SSH local forwards
#   status          Show managed SSH tunnel status
#   check           Verify remote 127.0.0.1:9100 binding and local tunnel /metrics
#
# Options:
#   --nodes "A C D" Node subset (default: "A C D"; reads hosts from cluster-nodes.conf)
#   --dry-run       Print planned remote & local commands without SSHing or mutating
#   --check         Run non-mutating check (equivalent to `check` command)
#   --no-tunnels    Only install/configure/verify remote node_exporter (skip local tunnels)
#   --tunnels-only  Only manage local SSH forwards (skip remote install/config)
#   --local-only    With --check, only curl local forwarded ports (skip SSH check)
#   -h, --help      Show this help
#
# Environment overrides:
#   STELL_CONF               Cluster config (default: scripts/cluster-nodes.conf)
#   NODE_EXP_STATE_DIR       Tunnel PID/log dir
#   NODE_EXP_REMOTE_PORT     Remote node_exporter port (default: 9100)
#   NODE_EXP_PORT_B          Local node B exporter port (default: 9101)
#   NODE_EXP_PORT_A/C/D      Local forwarded ports (default: 9102 / 9103 / 9104)
#   NODE_EXP_RECONNECT_SECS  SSH loop reconnect delay when autossh is absent (5)
#   NODE_EXP_TUNNEL_WAIT_SECS Max seconds to wait for local tunnel listen port (10)
#   NODE_EXP_CHECK_TIMEOUT   Curl timeout in seconds for --check (5)
#
# Exit codes: 0 ok, 1 check/remote/tunnel failure, 64 usage/config error.
# ==============================================================================
set -euo pipefail

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
CONF="${STELL_CONF:-$ROOT_DIR/scripts/cluster-nodes.conf}"

STATE_DIR="${NODE_EXP_STATE_DIR:-${XDG_RUNTIME_DIR:-$HOME/.local/state}/stellereum-node-exporter}"
REMOTE_PORT="${NODE_EXP_REMOTE_PORT:-9100}"
RECONNECT_SECS="${NODE_EXP_RECONNECT_SECS:-5}"
TUNNEL_WAIT_SECS="${NODE_EXP_TUNNEL_WAIT_SECS:-10}"
CHECK_TIMEOUT="${NODE_EXP_CHECK_TIMEOUT:-5}"
NODE_EXP_PORT_B="${NODE_EXP_PORT_B:-9101}"
NODE_EXP_PORT_A="${NODE_EXP_PORT_A:-9102}"
NODE_EXP_PORT_C="${NODE_EXP_PORT_C:-9103}"
NODE_EXP_PORT_D="${NODE_EXP_PORT_D:-9104}"

COMMAND=""
NODE_SPEC=""
DRY_RUN=0
NO_TUNNELS=0
TUNNELS_ONLY=0
LOCAL_ONLY=0
NODES=()

note() { printf '[setup-validator-monitoring] %s\n' "$*"; }
warn() { printf '[setup-validator-monitoring] WARN: %s\n' "$*" >&2; }
err()  { printf '[setup-validator-monitoring] ERROR: %s\n' "$*" >&2; }
die()  { err "$*"; exit 64; }

usage() { sed -n '2,/^# ====/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'; }

while [ $# -gt 0 ]; do
    case "$1" in
        setup|start|stop|restart|status|check)
            [ -z "$COMMAND" ] || die "multiple commands given: $COMMAND and $1"
            COMMAND="$1"
            shift
            ;;
        --check)
            COMMAND="check"
            shift
            ;;
        --nodes)
            [ $# -ge 2 ] || die "--nodes requires a value"
            NODE_SPEC="$2"
            shift 2
            ;;
        --nodes=*)
            NODE_SPEC="${1#*=}"
            shift
            ;;
        --dry-run) DRY_RUN=1; shift ;;
        --no-tunnels) NO_TUNNELS=1; shift ;;
        --tunnels-only) TUNNELS_ONLY=1; shift ;;
        --local-only) LOCAL_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown flag: $1" ;;
        *) die "unexpected argument: $1" ;;
    esac
done

[ -n "$COMMAND" ] || COMMAND="setup"

if [ "$NO_TUNNELS" -eq 1 ] && [ "$TUNNELS_ONLY" -eq 1 ]; then
    die "--no-tunnels and --tunnels-only cannot be combined"
fi

[ -r "$CONF" ] || die "cannot read cluster config: $CONF (set STELL_CONF)"
# shellcheck source=scripts/cluster-nodes.conf
. "$CONF"

node_attr() {
    local node="$1" attr="$2"
    local var="NODE_${node}_${attr}"
    printf '%s' "${!var:-}"
}

local_port_for() {
    local node="$1"
    local var="NODE_EXP_PORT_${node}"
    local val="${!var:-}"
    [ -n "$val" ] || die "no local forward port configured for node $node (set $var)"
    printf '%s' "$val"
}

read_nodes() {
    local spec="${1//,/ }"
    NODES=()
    if [ -n "$spec" ]; then
        read -r -a NODES <<<"$spec"
    else
        read -r -a NODES <<<"${STELL_MONITOR_NODES:-A C D}"
    fi
    [ "${#NODES[@]}" -gt 0 ] || die "no nodes selected"
    local n
    for n in "${NODES[@]}"; do
        [[ "$n" =~ ^[A-Za-z0-9_]+$ ]] || die "invalid node name: $n"
        # Validate a port mapping exists if it's a remote node
        if [ -n "$(node_attr "$n" SSH)" ]; then
            local_port_for "$n" >/dev/null
        fi
    done
}

read_nodes "$NODE_SPEC"

nrun() {
    local node="$1" cmd="$2" host opts
    host="$(node_attr "$node" SSH)"
    opts="$(node_attr "$node" SSH_OPTS)"
    [ -n "$host" ] || die "node $node has no NODE_${node}_SSH in $CONF"
    local -a ssh_opts=()
    if [ -n "$opts" ]; then
        read -r -a ssh_opts <<<"$opts"
    fi
    timeout 120 ssh -o BatchMode=yes -o ConnectTimeout=10 \
        -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
        "${ssh_opts[@]+"${ssh_opts[@]}"}" "$host" "$cmd"
}

pid_alive() {
    local pidfile="$1" pid
    [ -r "$pidfile" ] || return 1
    pid="$(cat "$pidfile" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

kill_group() {
    local pid="$1" i
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    for i in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.2
    done
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
}

remote_setup_script() {
    cat <<EOF
set -euo pipefail
SUDO=""
if [ "\$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || { echo "need root or sudo on remote host" >&2; exit 1; }
    SUDO="sudo"
fi

DESIRED_ADDR="127.0.0.1:${REMOTE_PORT}"
DESIRED_ARG="--web.listen-address=\${DESIRED_ADDR}"
DEFAULTS_FILE="/etc/default/prometheus-node-exporter"
CHANGED=0

# Pre-seed /etc/default/prometheus-node-exporter before package install so the
# service never binds 0.0.0.0:${REMOTE_PORT} even transiently during postinst.
if [ ! -f "\$DEFAULTS_FILE" ]; then
    \$SUDO install -d -m 0755 /etc/default
    printf 'ARGS="%s"\n' "\$DESIRED_ARG" | \$SUDO tee "\$DEFAULTS_FILE" >/dev/null
    CHANGED=1
fi

if ! command -v prometheus-node-exporter >/dev/null 2>&1; then
    command -v apt-get >/dev/null 2>&1 || { echo "apt-get not found; install prometheus-node-exporter manually bound to \$DESIRED_ADDR" >&2; exit 1; }
    \$SUDO apt-get update -qq
    \$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        prometheus-node-exporter
    CHANGED=1
fi

# Ensure ARGS in /etc/default/prometheus-node-exporter pins loopback-only address
# while preserving any non-listen flags (e.g. --collector.*).
if grep -qE '^ARGS=.*--web\.listen-address=127\.0\.0\.1:${REMOTE_PORT}([[:space:]"'\'']|\$)' "\$DEFAULTS_FILE" 2>/dev/null \
   && [ "\$(grep -oE -- '--web\.listen-address([=[:space:]]+[^[:space:]"'\'']+)?' "\$DEFAULTS_FILE" | wc -l)" -eq 1 ]; then
    :
else
    TMP_DEF="\$(mktemp)"
    if grep -qE '^ARGS=' "\$DEFAULTS_FILE"; then
        awk -v arg="\$DESIRED_ARG" '
            BEGIN { replaced=0; sq=sprintf("%c", 39) }
            /^ARGS=/ && !replaced {
                line = substr(\$0, 6)
                sub(/^[[:space:]]+/, "", line)
                sub(/[[:space:]]+\$/, "", line)
                if ((substr(line, 1, 1) == "\"" && substr(line, length(line), 1) == "\"") ||
                    (substr(line, 1, 1) == sq && substr(line, length(line), 1) == sq)) {
                    line = substr(line, 2, length(line) - 2)
                }
                n = split(line, toks, /[[:space:]]+/)
                kept = ""
                skip_next = 0
                for (i = 1; i <= n; i++) {
                    t = toks[i]
                    if (t == "") continue
                    if (skip_next) { skip_next = 0; continue }
                    if (t == "--web.listen-address") { skip_next = 1; continue }
                    if (index(t, "--web.listen-address=") == 1) { continue }
                    kept = (kept == "" ? t : kept " " t)
                }
                out = (kept == "" ? arg : arg " " kept)
                print "ARGS=\"" out "\""
                replaced=1
                next
            }
            { print }
        ' "\$DEFAULTS_FILE" > "\$TMP_DEF"
    else
        cat "\$DEFAULTS_FILE" > "\$TMP_DEF"
        printf '\nARGS="%s"\n' "\$DESIRED_ARG" >> "\$TMP_DEF"
    fi
    \$SUDO cp "\$TMP_DEF" "\$DEFAULTS_FILE"
    \$SUDO chmod 0644 "\$DEFAULTS_FILE"
    rm -f "\$TMP_DEF"
    CHANGED=1
fi

\$SUDO systemctl daemon-reload
\$SUDO systemctl enable prometheus-node-exporter >/dev/null 2>&1 || true
if [ "\$CHANGED" -eq 1 ] || ! \$SUDO systemctl is-active --quiet prometheus-node-exporter; then
    \$SUDO systemctl restart prometheus-node-exporter
fi

# Verify strictly loopback binding (never 0.0.0.0:${REMOTE_PORT} / [::]:${REMOTE_PORT} / *:${REMOTE_PORT})
sleep 1
LISTENERS="\$(ss -ltnH "sport = :${REMOTE_PORT}" 2>/dev/null || ss -ltn | awk '\$4 ~ /:${REMOTE_PORT}\$/')"
if [ -z "\$LISTENERS" ]; then
    echo "prometheus-node-exporter is not listening on :${REMOTE_PORT}" >&2
    exit 1
fi
NON_LOOPBACK="\$(printf '%s\n' "\$LISTENERS" | awk '{print \$4}' | grep -v -E '^127\.0\.0\.1:${REMOTE_PORT}\$' || true)"
if [ -n "\$NON_LOOPBACK" ]; then
    echo "REFUSING non-loopback listener(s) on :${REMOTE_PORT}: \$NON_LOOPBACK" >&2
    exit 1
fi
echo "OK prometheus-node-exporter listening strictly on 127.0.0.1:${REMOTE_PORT}"
EOF
}

remote_check_script() {
    cat <<EOF
set -euo pipefail
systemctl is-active --quiet prometheus-node-exporter || { echo "service prometheus-node-exporter is not active" >&2; exit 1; }
LISTENERS="\$(ss -ltnH "sport = :${REMOTE_PORT}" 2>/dev/null || ss -ltn | awk '\$4 ~ /:${REMOTE_PORT}\$/')"
[ -n "\$LISTENERS" ] || { echo "nothing listening on :${REMOTE_PORT}" >&2; exit 1; }
NON_LOOPBACK="\$(printf '%s\n' "\$LISTENERS" | awk '{print \$4}' | grep -v -E '^127\.0\.0\.1:${REMOTE_PORT}\$' || true)"
if [ -n "\$NON_LOOPBACK" ]; then
    echo "non-loopback listener(s) detected on :${REMOTE_PORT}: \$NON_LOOPBACK" >&2
    exit 1
fi
echo "127.0.0.1:${REMOTE_PORT}"
EOF
}

setup_remote_one() {
    local node="$1" host opts
    host="$(node_attr "$node" SSH)"
    opts="$(node_attr "$node" SSH_OPTS)"
    if [ -z "$host" ]; then
        note "[$node] local node (NODE_${node}_SSH empty); covered by job 'node' on 127.0.0.1:9101 — skipping remote setup"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        note "[DRY-RUN][$node] ssh ${opts:+$opts }$host: idempotently install/configure prometheus-node-exporter on 127.0.0.1:$REMOTE_PORT (/etc/default/prometheus-node-exporter ARGS=\"--web.listen-address=127.0.0.1:$REMOTE_PORT\"), enable+restart if changed, assert ss -ltn has only 127.0.0.1:$REMOTE_PORT"
        return 0
    fi
    note "[$node] configuring prometheus-node-exporter on $host (127.0.0.1:$REMOTE_PORT only)..."
    local script
    script="$(remote_setup_script)"
    nrun "$node" "bash -s" <<<"$script"
}

start_tunnel_one() {
    local node="$1" host opts port pidfile log
    host="$(node_attr "$node" SSH)"
    opts="$(node_attr "$node" SSH_OPTS)"
    if [ -z "$host" ]; then
        note "[$node] local node (no SSH tunnel needed)"
        return 0
    fi
    port="$(local_port_for "$node")"
    pidfile="$STATE_DIR/$node.pid"
    log="$STATE_DIR/$node.log"

    if [ "$DRY_RUN" -eq 1 ]; then
        note "[DRY-RUN][$node] open SSH local forward 127.0.0.1:$port -> $host 127.0.0.1:$REMOTE_PORT (via autossh/ssh under setsid, pidfile=$pidfile)"
        return 0
    fi

    mkdir -p -m 0700 "$STATE_DIR"
    chmod 0700 "$STATE_DIR" 2>/dev/null || true

    if pid_alive "$pidfile"; then
        note "[$node] tunnel already running (pid $(cat "$pidfile"), 127.0.0.1:$port -> $host:127.0.0.1:$REMOTE_PORT)"
        return 0
    fi
    rm -f "$pidfile"

    local -a extra=()
    if [ -n "$opts" ]; then
        read -r -a extra <<<"$opts"
    fi

    local -a forward=(
        -N -T
        -o ExitOnForwardFailure=yes
        -o ServerAliveInterval=15
        -o ServerAliveCountMax=3
        -o TCPKeepAlive=yes
        -o ConnectTimeout=10
        -o BatchMode=yes
        -L "127.0.0.1:${port}:127.0.0.1:${REMOTE_PORT}"
    )

    local has_setsid=0
    command -v setsid >/dev/null 2>&1 && has_setsid=1

    if command -v autossh >/dev/null 2>&1; then
        if [ "$has_setsid" -eq 1 ]; then
            AUTOSSH_GATETIME=0 setsid autossh -M 0 "${forward[@]}" "${extra[@]}" "$host" >>"$log" 2>&1 &
        else
            AUTOSSH_GATETIME=0 autossh -M 0 "${forward[@]}" "${extra[@]}" "$host" >>"$log" 2>&1 &
        fi
        echo "$!" >"$pidfile"
        note "[$node] autossh tunnel started: 127.0.0.1:$port -> $host:127.0.0.1:$REMOTE_PORT (pid $!)"
        return 0
    fi

    local supervisor='
        host=$1; port=$2; remote=$3; log=$4; reconnect=$5
        shift 5
        while :; do
            ssh -N -T \
                -o ExitOnForwardFailure=yes \
                -o ServerAliveInterval=15 \
                -o ServerAliveCountMax=3 \
                -o TCPKeepAlive=yes \
                -o ConnectTimeout=10 \
                -o BatchMode=yes \
                -L "127.0.0.1:${port}:127.0.0.1:${remote}" "$@" "$host" >>"$log" 2>&1
            rc=$?
            printf "%s ssh exited rc=%s; reconnecting in %ss\n" "$(date -Is)" "$rc" "$reconnect" >>"$log"
            sleep "$reconnect"
        done
    '
    if [ "$has_setsid" -eq 1 ]; then
        setsid bash -c "$supervisor" bash "$host" "$port" "$REMOTE_PORT" "$log" "$RECONNECT_SECS" "${extra[@]}" >>"$log" 2>&1 &
    else
        bash -c "$supervisor" bash "$host" "$port" "$REMOTE_PORT" "$log" "$RECONNECT_SECS" "${extra[@]}" >>"$log" 2>&1 &
    fi
    echo "$!" >"$pidfile"
    note "[$node] ssh tunnel loop started: 127.0.0.1:$port -> $host:127.0.0.1:$REMOTE_PORT (pid $!)"
}

port_listening() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltnH "sport = :${port}" 2>/dev/null | grep -qE "(127\.0\.0\.1|\[::1\]):${port}[[:space:]]" && return 0
        ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "^(127\.0\.0\.1|\[::1\]):${port}$" && return 0
        return 1
    fi
    (exec 3<>"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1
}

verify_tunnel_one() {
    local node="$1" host port pidfile log deadline
    host="$(node_attr "$node" SSH)"
    [ -n "$host" ] || return 0
    if [ "$DRY_RUN" -eq 1 ]; then
        port="$(local_port_for "$node")"
        note "[DRY-RUN][$node] verify 127.0.0.1:$port is listening"
        return 0
    fi
    port="$(local_port_for "$node")"
    pidfile="$STATE_DIR/$node.pid"
    log="$STATE_DIR/$node.log"
    deadline=$(( $(date +%s) + TUNNEL_WAIT_SECS ))
    while :; do
        if port_listening "$port"; then
            note "[$node] verified local tunnel listening on 127.0.0.1:$port"
            return 0
        fi
        if ! pid_alive "$pidfile"; then
            err "[$node] tunnel process exited before 127.0.0.1:$port began listening (see $log)"
            [ -r "$log" ] && tail -n 5 "$log" >&2 || true
            return 1
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            err "[$node] timed out after ${TUNNEL_WAIT_SECS}s waiting for 127.0.0.1:$port to listen (see $log)"
            [ -r "$log" ] && tail -n 5 "$log" >&2 || true
            return 1
        fi
        sleep 0.5
    done
}

stop_tunnel_one() {
    local node="$1" host pidfile="$STATE_DIR/$1.pid" pid
    host="$(node_attr "$node" SSH)"
    if [ -z "$host" ]; then
        note "[$node] local node (no SSH tunnel managed)"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        note "[DRY-RUN][$node] stop tunnel pidfile $pidfile"
        return 0
    fi
    if ! pid_alive "$pidfile"; then
        rm -f "$pidfile"
        note "[$node] tunnel not running"
        return 0
    fi
    pid="$(cat "$pidfile")"
    kill_group "$pid"
    rm -f "$pidfile"
    note "[$node] tunnel stopped (pid $pid)"
}

status_tunnel_one() {
    local node="$1" host port pidfile="$STATE_DIR/$1.pid"
    host="$(node_attr "$node" SSH)"
    if [ -z "$host" ]; then
        note "[$node] local node (host metrics on 127.0.0.1:9101 via docker-compose)"
        return 0
    fi
    port="$(local_port_for "$node")"
    if pid_alive "$pidfile"; then
        note "[$node] UP (pid $(cat "$pidfile")): http://127.0.0.1:$port/metrics -> $host:127.0.0.1:$REMOTE_PORT"
    else
        note "[$node] DOWN (expected 127.0.0.1:$port -> $host:127.0.0.1:$REMOTE_PORT)"
    fi
}

check_one() {
    local node="$1" host port url remote_res body
    host="$(node_attr "$node" SSH)"
    if [ -z "$host" ]; then
        port="$(local_port_for "$node")"
        url="http://127.0.0.1:${port}/metrics"
        if [ "$DRY_RUN" -eq 1 ]; then
            note "[DRY-RUN][$node] check local node_exporter: curl -fsS --max-time $CHECK_TIMEOUT $url (expect node_filesystem_avail_bytes & node_filesystem_files_free)"
            return 0
        fi
        if ! body="$(curl -fsS --max-time "$CHECK_TIMEOUT" "$url" 2>/dev/null)"; then
            err "[$node] local node_exporter check FAILED: curl $url failed"
            return 1
        fi
        if ! grep -q '^node_filesystem_avail_bytes' <<<"$body" || ! grep -q '^node_filesystem_files_free' <<<"$body"; then
            err "[$node] metrics at $url missing node_filesystem_avail_bytes or node_filesystem_files_free"
            return 1
        fi
        note "[$node] OK: local=$url (disk & inode metrics present)"
        return 0
    fi
    port="$(local_port_for "$node")"
    url="http://127.0.0.1:${port}/metrics"

    if [ "$DRY_RUN" -eq 1 ]; then
        if [ "$LOCAL_ONLY" -eq 0 ]; then
            note "[DRY-RUN][$node] check remote $host: prometheus-node-exporter active & listening strictly on 127.0.0.1:$REMOTE_PORT"
        fi
        note "[DRY-RUN][$node] check local forward: curl -fsS --max-time $CHECK_TIMEOUT $url (expect node_filesystem_avail_bytes & node_filesystem_files_free)"
        return 0
    fi

    if [ "$LOCAL_ONLY" -eq 0 ]; then
        local rscript
        rscript="$(remote_check_script)"
        if ! remote_res="$(nrun "$node" "bash -s" <<<"$rscript" 2>&1)"; then
            err "[$node] remote check FAILED: $remote_res"
            return 1
        fi
    else
        remote_res="skipped (--local-only)"
    fi

    if ! body="$(curl -fsS --max-time "$CHECK_TIMEOUT" "$url" 2>/dev/null)"; then
        err "[$node] local forward check FAILED: curl $url failed (remote=$remote_res)"
        return 1
    fi

    if ! grep -q '^node_filesystem_avail_bytes' <<<"$body" || ! grep -q '^node_filesystem_files_free' <<<"$body"; then
        err "[$node] metrics at $url missing node_filesystem_avail_bytes or node_filesystem_files_free"
        return 1
    fi

    note "[$node] OK: remote=$remote_res local=$url (disk & inode metrics present)"
    return 0
}

print_prometheus_note() {
    note "Prometheus targets (uncomment job 'validator-hosts' in ops/observability/prometheus.yml once --check passes):"
    local n port
    for n in "${NODES[@]}"; do
        [ -n "$(node_attr "$n" SSH)" ] || continue
        port="$(local_port_for "$n")"
        printf '  node=%s  127.0.0.1:%s  (-> %s:127.0.0.1:%s)\n' "$n" "$port" "$(node_attr "$n" SSH)" "$REMOTE_PORT"
    done
}

case "$COMMAND" in
    setup)
        if [ "$DRY_RUN" -eq 1 ]; then
            note "DRY RUN — no SSH connections, package installs, or tunnels will be started"
            note "config: $CONF"
            note "nodes:  ${NODES[*]}"
        fi
        if [ "$TUNNELS_ONLY" -eq 0 ]; then
            for n in "${NODES[@]}"; do
                setup_remote_one "$n"
            done
        fi
        if [ "$NO_TUNNELS" -eq 0 ]; then
            for n in "${NODES[@]}"; do
                start_tunnel_one "$n"
            done
            tunnel_fail=0
            for n in "${NODES[@]}"; do
                verify_tunnel_one "$n" || tunnel_fail=1
            done
            [ "$tunnel_fail" -eq 0 ] || exit 1
        fi
        print_prometheus_note
        ;;
    start)
        if [ "$DRY_RUN" -eq 1 ]; then
            note "DRY RUN — no SSH connections or tunnels will be started"
        fi
        if [ "$TUNNELS_ONLY" -eq 0 ]; then
            for n in "${NODES[@]}"; do
                setup_remote_one "$n"
            done
        fi
        if [ "$NO_TUNNELS" -eq 0 ]; then
            for n in "${NODES[@]}"; do
                start_tunnel_one "$n"
            done
            tunnel_fail=0
            for n in "${NODES[@]}"; do
                verify_tunnel_one "$n" || tunnel_fail=1
            done
            [ "$tunnel_fail" -eq 0 ] || exit 1
        fi
        print_prometheus_note
        ;;
    stop)
        for n in "${NODES[@]}"; do
            stop_tunnel_one "$n"
        done
        ;;
    restart)
        for n in "${NODES[@]}"; do
            stop_tunnel_one "$n"
        done
        for n in "${NODES[@]}"; do
            start_tunnel_one "$n"
        done
        tunnel_fail=0
        for n in "${NODES[@]}"; do
            verify_tunnel_one "$n" || tunnel_fail=1
        done
        [ "$tunnel_fail" -eq 0 ] || exit 1
        ;;
    status)
        for n in "${NODES[@]}"; do
            status_tunnel_one "$n"
        done
        ;;
    check)
        ok_count=0
        total_count=0
        check_nodes=("${NODES[@]}")
        if [ -z "$NODE_SPEC" ]; then
            has_b=0
            for n in "${check_nodes[@]}"; do
                [ "$n" = "B" ] && has_b=1
            done
            [ "$has_b" -eq 1 ] || check_nodes=(B "${check_nodes[@]}")
        fi
        for n in "${check_nodes[@]}"; do
            total_count=$((total_count + 1))
            if check_one "$n"; then
                ok_count=$((ok_count + 1))
            fi
        done
        if [ "$DRY_RUN" -eq 1 ]; then
            note "DRY RUN check complete (would verify $total_count validator endpoint(s))"
            exit 0
        fi
        note "RESULT ${ok_count}/${total_count} validator node_exporter endpoints healthy"
        [ "$ok_count" -eq "$total_count" ]
        ;;
esac
