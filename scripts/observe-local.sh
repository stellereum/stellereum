#!/usr/bin/env bash
# ==============================================================================
# observe-local.sh — run the SSH tunnels Prometheus scrapes for the live
# 4-validator cluster.
#
# WHY SSH TUNNELS: every node binds its Prometheus endpoint to 127.0.0.1
# (STELL_EXPLORER_LISTEN=127.0.0.1:8080), so a remote collector cannot scrape
# it and the endpoint is not reachable from the internet at all. This script
# forwards each remote loopback port to a distinct LOCAL loopback port:
#
#   node A  root@212.113.103.105:22    local 127.0.0.1:9080
#   node C  root@213.21.246.5:2222     local 127.0.0.1:9081
#   node D  root@138.124.102.200:22    local 127.0.0.1:9082
#   node B  this host (systemd --user) local 127.0.0.1:18081 (no tunnel)
#
# 9083 is reserved for a fifth endpoint. Hosts/ports come from
# scripts/cluster-nodes.conf, never from values duplicated here.
#
# Reconnect behaviour:
#   * autossh installed -> `autossh -M 0` with ServerAliveInterval=15;
#   * otherwise        -> a supervisor loop that restarts ssh after a drop.
#   Both are started under setsid so the tunnel survives this script exiting
#   and `stop` can kill the whole process group.
#
# Usage:
#   scripts/observe-local.sh start      # start A/C/D tunnels + print URLs
#   scripts/observe-local.sh status
#   scripts/observe-local.sh stop
#   scripts/observe-local.sh restart
#   scripts/observe-local.sh --check    # curl all four, one line per node
#
# Exit codes: 0 ok, 1 one or more nodes unreachable (--check), 64 usage/config.
# This script never writes to a node and never restarts one. It only opens
# client-side ssh forwards.
# ==============================================================================
set -uo pipefail

PROG="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONF="${STELL_CONF:-$ROOT_DIR/scripts/cluster-nodes.conf}"

STATE_DIR="${OBS_STATE_DIR:-${XDG_RUNTIME_DIR:-$HOME/.local/state}/stellereum-observe}"
OBS_REMOTE_PORT="${OBS_REMOTE_PORT:-8080}"
OBS_RECONNECT_SECS="${OBS_RECONNECT_SECS:-5}"
OBS_CHECK_TIMEOUT="${OBS_CHECK_TIMEOUT:-5}"
OBS_PORT_A="${OBS_PORT_A:-9080}"
OBS_PORT_C="${OBS_PORT_C:-9081}"
OBS_PORT_D="${OBS_PORT_D:-9082}"
OBS_PORT_B="${OBS_PORT_B:-18081}"

die()  { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 64; }
info() { printf '%s\n' "$*"; }
warn() { printf '%s: %s\n' "$PROG" "$*" >&2; }

[ -r "$CONF" ] || die "cannot read node config: $CONF (set STELL_CONF)"
# shellcheck source=scripts/cluster-nodes.conf
. "$CONF"

NODE_ORDER=(A C D)

local_port() {
  case "$1" in
    A) printf '%s' "$OBS_PORT_A" ;;
    C) printf '%s' "$OBS_PORT_C" ;;
    D) printf '%s' "$OBS_PORT_D" ;;
    B) printf '%s' "$OBS_PORT_B" ;;
    *) return 1 ;;
  esac
}

ssh_host() {
  local var="NODE_${1}_SSH"
  printf '%s' "${!var:-}"
}

ssh_opts() {
  local var="NODE_${1}_SSH_OPTS"
  printf '%s' "${!var:-}"
}

metrics_url() {
  printf 'http://127.0.0.1:%s/metrics' "$(local_port "$1")"
}

pid_alive() {
  local pidfile="$1" pid
  [ -r "$pidfile" ] || return 1
  pid="$(cat "$pidfile" 2>/dev/null)" || return 1
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

print_targets() {
  info ""
  info "Scrape targets for Prometheus job \"stell-nodes\":"
  printf '  %-2s %-32s %s\n' "A" "$(metrics_url A)" "ssh tunnel -> $(ssh_host A):$OBS_REMOTE_PORT"
  printf '  %-2s %-32s %s\n' "B" "$(metrics_url B)" "local process (no tunnel)"
  printf '  %-2s %-32s %s\n' "C" "$(metrics_url C)" "ssh tunnel -> $(ssh_host C):$OBS_REMOTE_PORT"
  printf '  %-2s %-32s %s\n' "D" "$(metrics_url D)" "ssh tunnel -> $(ssh_host D):$OBS_REMOTE_PORT"
  info ""
  info "Next: ops/observability/docker-compose.yml, then $PROG --check"
}

start_one() {
  local name="$1" port host opts pidfile log
  port="$(local_port "$name")"
  host="$(ssh_host "$name")"
  opts="$(ssh_opts "$name")"
  pidfile="$STATE_DIR/$name.pid"
  log="$STATE_DIR/$name.log"

  if [ -z "$host" ]; then
    warn "node $name: no NODE_${name}_SSH in $CONF; skipping tunnel"
    return 1
  fi

  if pid_alive "$pidfile"; then
    info "node $name: tunnel already running (pid $(cat "$pidfile"), local port $port)"
    return 0
  fi
  rm -f "$pidfile"

  local -a extra=()
  if [ -n "$opts" ]; then
    # NODE_C_SSH_OPTS="-p 2222": word splitting is intentional, it is an ssh
    # option list from the shared config.
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
    -L "127.0.0.1:${port}:127.0.0.1:${OBS_REMOTE_PORT}"
  )

  local has_setsid=0
  command -v setsid >/dev/null 2>&1 && has_setsid=1

  if command -v autossh >/dev/null 2>&1; then
    # -M 0: no monitoring port; ServerAlive* is the liveness check.
    # GATETIME=0 keeps retrying even if the first connection fails fast.
    if [ "$has_setsid" -eq 1 ]; then
      AUTOSSH_GATETIME=0 setsid autossh -M 0 "${forward[@]}" "${extra[@]}" "$host" >>"$log" 2>&1 &
    else
      AUTOSSH_GATETIME=0 autossh -M 0 "${forward[@]}" "${extra[@]}" "$host" >>"$log" 2>&1 &
    fi
    echo "$!" >"$pidfile"
    info "node $name: autossh tunnel 127.0.0.1:$port -> $host:$OBS_REMOTE_PORT (pid $!)"
    return 0
  fi

  # No autossh: supervisor loop. Parameters are passed positionally so the
  # reconnect loop never re-parses this script.
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
    setsid bash -c "$supervisor" bash "$host" "$port" "$OBS_REMOTE_PORT" "$log" "$OBS_RECONNECT_SECS" "${extra[@]}" >>"$log" 2>&1 &
  else
    bash -c "$supervisor" bash "$host" "$port" "$OBS_REMOTE_PORT" "$log" "$OBS_RECONNECT_SECS" "${extra[@]}" >>"$log" 2>&1 &
  fi
  echo "$!" >"$pidfile"
  info "node $name: ssh supervision loop 127.0.0.1:$port -> $host:$OBS_REMOTE_PORT (pid $!)"
  return 0
}

kill_group() {
  local pid="$1" i
  # Negative pid targets the process group when the tunnel was started under
  # setsid; the plain kill is the fallback when setsid was unavailable.
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  for i in 1 2 3 4 5 6 7 8 9 10; do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.2
  done
  kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
}

stop_one() {
  local name="$1" pidfile="$STATE_DIR/$1.pid" pid
  if ! pid_alive "$pidfile"; then
    rm -f "$pidfile"
    info "node $name: not running"
    return 0
  fi
  pid="$(cat "$pidfile")"
  kill_group "$pid"
  rm -f "$pidfile"
  info "node $name: stopped (pid $pid)"
}

cmd_start() {
  mkdir -p -m 0700 "$STATE_DIR" || die "cannot create state dir: $STATE_DIR"
  chmod 0700 "$STATE_DIR" 2>/dev/null || true
  local name
  for name in "${NODE_ORDER[@]}"; do
    start_one "$name"
  done
  print_targets
}

cmd_stop() {
  local name
  for name in "${NODE_ORDER[@]}"; do
    stop_one "$name"
  done
}

cmd_status() {
  local name pidfile
  for name in A B C D; do
    if [ "$name" = B ]; then
      info "node B: local process on 127.0.0.1:$OBS_PORT_B (not managed by $PROG)"
      continue
    fi
    pidfile="$STATE_DIR/$name.pid"
    if pid_alive "$pidfile"; then
      info "node $name: tunnel pid $(cat "$pidfile") -> $(metrics_url "$name")"
    else
      info "node $name: down (no live tunnel; run $PROG start)"
    fi
  done
}

cmd_check() {
  local name url body state height ready ok=0 total=0
  printf '%-4s %-6s %-30s %s\n' "NODE" "STATE" "URL" "DETAIL"
  for name in A B C D; do
    url="$(metrics_url "$name")"
    total=$((total + 1))
    height="-"
    if body="$(curl -fsS --max-time "$OBS_CHECK_TIMEOUT" "$url" 2>/dev/null)"; then
      height="$(printf '%s\n' "$body" | awk '$1 == "stell_consensus_height" { print $2; exit }')"
      [ -n "$height" ] || height="no-height-series"
      state="OK"
      ok=$((ok + 1))
      printf '%-4s %-6s %-30s height=%s\n' "$name" "$state" "$url" "$height"
    else
      state="DOWN"
      printf '%-4s %-6s %-30s curl failed (node or tunnel down)\n' "$name" "$state" "$url"
    fi
  done
  printf 'RESULT %d/%d nodes reachable\n' "$ok" "$total"
  [ "$ok" -eq "$total" ]
}

usage() {
  cat <<EOF
$PROG — SSH tunnels for the 127.0.0.1-bound node /metrics endpoints

Usage:
  $PROG start      start A/C/D tunnels (A:9080, C:9081, D:9082), print URLs
  $PROG status     show tunnel PIDs (B is local, not managed)
  $PROG stop       stop the tunnels
  $PROG restart    stop + start
  $PROG --check    curl all four nodes; one line per node; exit 1 if < 4/4

Hosts and ssh options come from ${CONF}.
Env overrides: STELL_CONF, OBS_STATE_DIR, OBS_PORT_A/C/D/B,
OBS_REMOTE_PORT (default 8080), OBS_RECONNECT_SECS, OBS_CHECK_TIMEOUT.

The metrics endpoint is bound to each node's loopback on purpose: it is
unauthenticated and exposes peer/validator ids. Do not expose it publicly.
EOF
}

case "${1:-start}" in
  start|up) cmd_start ;;
  stop|down) cmd_stop ;;
  restart) cmd_stop; cmd_start ;;
  status) cmd_status ;;
  check|--check) cmd_check ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 64 ;;
esac
