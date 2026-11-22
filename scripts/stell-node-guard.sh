#!/usr/bin/env bash
# Stellereum node guard (repo copy).
#
# Safe by construction: this script restarts ONLY a unit that is NOT running
# (inactive/failed/dead). An ACTIVE but STALLED node is never restarted here —
# stalls have their own recovery path and a blind restart mid-consensus is
# worse than the stall. Every decision is appended to the guard log.
#
# Optional validator watch (no auto-unjail: that needs the COLD key):
#   STELL_GUARD_VALIDATOR=<64-hex validator id>
#     * jailed AND current height >= release_height -> ALERT at most once per
#       STELL_GUARD_ALERT_SECS (default 600 = 10 min), with the exact command.
#     * withdrawal_address == null -> ONE-TIME ALERT that this validator is
#       unmanageable until ClaimWithdrawal (OpCode 62) claims a cold address.
#
# Env (all optional):
#   STELL_GUARD_VALIDATOR   validator id to watch
#   STELL_GUARD_RPC         JSON-RPC URL (default http://127.0.0.1:8545)
#   STELL_GUARD_UNITS       space-separated systemd units; default: every
#                           installed stell-node*.service on this host.
#                           STELL_GUARD_UNIT (singular) is accepted as an alias.
#   STELL_GUARD_SCOPE       `system` (default) or `user` for a --user unit
#   STELL_GUARD_LOG         decision log (default /var/log/stell-node-guard.log)
#   STELL_GUARD_STATE_DIR   alert throttle/one-time markers
#                           (default /var/lib/stell-node-guard)
#   STELL_GUARD_ALERT_SECS  jailed-alert throttle (default 600)
#   STELL_GUARD_INTERVAL_SECS  sleep between passes for --loop (default 60)
#
# Usage:
#   stell-node-guard.sh            one pass (cron/systemd timer friendly)
#   stell-node-guard.sh --once     one pass (explicit)
#   stell-node-guard.sh --loop     continuous passes every STELL_GUARD_INTERVAL_SECS
#   stell-node-guard.sh -h|--help  this text
set -u

VALIDATOR="${STELL_GUARD_VALIDATOR:-}"
RPC="${STELL_GUARD_RPC:-http://127.0.0.1:8545}"
UNITS="${STELL_GUARD_UNITS:-${STELL_GUARD_UNIT:-}}"
SCOPE="${STELL_GUARD_SCOPE:-system}"
LOG="${STELL_GUARD_LOG:-/var/log/stell-node-guard.log}"
STATE_DIR="${STELL_GUARD_STATE_DIR:-/var/lib/stell-node-guard}"
ALERT_SECS="${STELL_GUARD_ALERT_SECS:-600}"
INTERVAL_SECS="${STELL_GUARD_INTERVAL_SECS:-60}"

usage() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
}

# systemd in the requested scope (nodeB runs a --user unit).
stctl() {
  if [ "$SCOPE" = "user" ]; then
    systemctl --user "$@"
  else
    systemctl "$@"
  fi
}

log() {
  local line
  line="$(date -u +%FT%TZ) [stell-guard] $*"
  printf '%s\n' "$line" >>"$LOG" 2>/dev/null || printf '%s\n' "$line" >&2
}

rpc() {
  local method="$1" params="${2:-[]}"
  curl -sS -m 5 -X POST "$RPC" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    2>/dev/null
}

json_str() {
  local key="$1" body="$2"
  printf '%s' "$body" | sed -n 's/.*"'"$key"'":"\([^"]*\)".*/\1/p' | head -1
}

json_num() {
  local key="$1" body="$2"
  printf '%s' "$body" | sed -n 's/.*"'"$key"'":\([0-9][0-9]*\).*/\1/p' | head -1
}

json_bool() {
  local key="$1" body="$2"
  printf '%s' "$body" | sed -n 's/.*"'"$key"'":\(true\|false\).*/\1/p' | head -1
}

block_height() {
  local body result
  body="$(rpc stell_blockNumber '[]')"
  [ -n "$body" ] || return 1
  result="$(json_str result "$body")"
  [ -n "$result" ] || return 1
  case "$result" in
    0x*|0X*)
      result="${result#0[Xx]}"
      printf '%d\n' "$((16#$result))"
      ;;
    *) printf '%s\n' "$result" ;;
  esac
}

ensure_state_dir() {
  if mkdir -p "$STATE_DIR" 2>/dev/null && [ -w "$STATE_DIR" ]; then
    return 0
  fi
  # Non-root run / read-only /var: keep the throttles working out of /tmp.
  STATE_DIR="${TMPDIR:-/tmp}/stell-node-guard-$(id -u)"
  mkdir -p "$STATE_DIR" 2>/dev/null || true
}

alert_throttled() {
  local key="$1" msg="$2" marker now last
  marker="$STATE_DIR/$key.last"
  now="$(date +%s)"
  last="$(cat "$marker" 2>/dev/null || true)"
  case "$last" in
    ''|*[!0-9]*) last=0 ;;
  esac
  if [ $((now - last)) -lt "$ALERT_SECS" ]; then
    return 0
  fi
  printf '%s\n' "$now" >"$marker" 2>/dev/null || true
  log "ALERT $msg"
}

alert_once() {
  local key="$1" msg="$2" marker
  marker="$STATE_DIR/$key.once"
  if [ -e "$marker" ]; then
    return 0
  fi
  printf '%s\n' "$(date +%s)" >"$marker" 2>/dev/null || true
  log "ALERT $msg"
}

guard_validator() {
  [ -n "$VALIDATOR" ] || return 0

  local body known withdrawal jailed release height
  body="$(rpc stell_getValidatorStatus "{\"validator\":\"$VALIDATOR\"}")"
  if [ -z "$body" ]; then
    log "WARN validator status query returned nothing (RPC $RPC unreachable?)"
    return 0
  fi
  if printf '%s' "$body" | grep -q '"error"'; then
    log "WARN validator status query failed: $body"
    return 0
  fi

  known="$(json_bool known "$body")"
  if [ "$known" != "true" ]; then
    log "WARN validator $VALIDATOR has no staking record on this node's ledger"
    return 0
  fi

  withdrawal="$(json_str withdrawal_address "$body")"
  if [ -z "$withdrawal" ]; then
    # One-time per validator: this cannot be fixed by restarting or waiting.
    alert_once "unmanageable-$VALIDATOR" \
      "validator $VALIDATOR has NO withdrawal_address: unjail/unbond/withdraw/reward-claim/commission are ALL refused until ClaimWithdrawal (OpCode 62) claims a cold address. Run: stellereum validator claim-withdrawal --validator-id $VALIDATOR --voting-key-file ./keys/falcon.key --withdrawal-key-file <cold-withdrawal-key> (use --dry-run first). NO auto-recovery is possible with the hot key alone"
  else
    # A later successful ClaimWithdrawal re-arms the one-time alert.
    rm -f "$STATE_DIR/unmanageable-$VALIDATOR.once" 2>/dev/null || true
  fi

  jailed="$(json_bool jailed "$body")"
  release="$(json_num release_height "$body")"
  [ "$jailed" = "true" ] || return 0

  if ! height="$(block_height)" || [ -z "$height" ]; then
    log "WARN validator $VALIDATOR is jailed but the current height is unavailable"
    return 0
  fi

  if [ -n "$release" ] && [ "$height" -ge "$release" ]; then
    # Throttled: at most once per ALERT_SECS (default 10 min). NO auto-unjail:
    # the unjail MUST be signed by the cold withdrawal key.
    alert_throttled "jailed-$VALIDATOR" \
      "validator $VALIDATOR is JAILED and PAST release_height $release (current height $height) but the jail is still present. This is the nodeB incident shape: no automatic recovery. Run: stellereum validator unjail --validator-id $VALIDATOR --withdrawal-key-file <cold-withdrawal-key> (if the record has no withdrawal_address, run claim-withdrawal FIRST)"
  else
    log "INFO validator $VALIDATOR jailed; release_height ${release:-unknown} (current height $height)"
  fi
}

discover_units() {
  if [ -n "$UNITS" ]; then
    # Word-splitting is intentional: UNITS is a space-separated list.
    # shellcheck disable=SC2086
    printf '%s\n' $UNITS
    return 0
  fi
  stctl list-unit-files --type=service --no-legend 'stell-node*.service' 2>/dev/null \
    | awk '{print $1}'
}

guard_units() {
  local unit state
  while IFS= read -r unit; do
    [ -n "$unit" ] || continue
    # Never touch a unit that is not installed on this host.
    if ! stctl cat "$unit" >/dev/null 2>&1; then
      continue
    fi
    state="$(stctl is-active "$unit" 2>/dev/null || true)"
    case "$state" in
      active|activating|reloading)
        # ALIVE, even if stalled: never restart a running node from here.
        continue
        ;;
    esac
    log "unit $unit is NOT running (state=${state:-unknown}); restarting only this dead unit"
    if ! stctl restart "$unit"; then
      log "ERROR stctl restart $unit failed"
    fi
  done <<EOF
$(discover_units)
EOF
}

run_once() {
  ensure_state_dir
  guard_units
  guard_validator
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  --once|"")
    run_once
    ;;
  --loop)
    while true; do
      run_once
      sleep "$INTERVAL_SECS"
    done
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
