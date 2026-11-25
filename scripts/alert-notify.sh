#!/usr/bin/env bash
# alert-notify.sh — deliver Alertmanager alerts without a third-party channel.
#
# WHY: Alertmanager with the "null" receiver keeps alerts active but tells no
# one. During the 2026-11-24 halt, ValidatorQuorumLow sat active for hours and
# was noticed by a human, not by an alert. Telegram works but needs a bot token;
# this script closes the loop with no secret at all.
#
# WHAT IT DOES (one pass; run from a timer every minute):
#   1. GET <alertmanager>/api/v2/alerts?active=true&silenced=false&inhibited=false
#   2. Diff against a small state file: report only NEW alerts, and report an
#      alert once as RESOLVED when it disappears (no repeat spam).
#   3. Append a one-line-per-event record to the log and, if STELL_ALERT_HOOK is
#      set, run it with the line on stdin (curl to a webhook, a chat bot, wall…).
#
# Usage:
#   alert-notify.sh            one pass
#   alert-notify.sh --loop 60  poll every 60 s (systemd Type=simple)
#   alert-notify.sh --state /path/alerts.state   where last-seen labels live
#
# Exit: 0 always (a monitoring helper must not flap); errors are logged.
set -u

AM_URL="${STELL_ALERTMANAGER_URL:-http://127.0.0.1:9093}"
DEFAULT_STATE_DIR="${XDG_RUNTIME_DIR:-$HOME/.local/state}/stellereum-alert-notify"
STATE="${STELL_ALERT_STATE:-$DEFAULT_STATE_DIR/state}"
LOG="${STELL_ALERT_LOG:-/var/log/stell-alerts.log}"
HOOK="${STELL_ALERT_HOOK:-}"
LOOP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --loop) LOOP="${2:?--loop needs seconds}"; shift 2 ;;
        --state) STATE="${2:?--state needs a path}"; shift 2 ;;
        --once) LOOP=0; shift ;;
        -h|--help) sed -n '1,26p' "$0"; exit 0 ;;
        *) echo "alert-notify.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done

mkdir -p -m 0700 "$(dirname "$STATE")" 2>/dev/null || true
chmod 0700 "$DEFAULT_STATE_DIR" 2>/dev/null || true

emit() {
    local line="$1"
    printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$line" >>"$LOG" 2>/dev/null ||
        printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$line"
    printf '%s\n' "$line"
    if [ -n "$HOOK" ]; then
        printf '%s\n' "$line" | sh -c "$HOOK" >/dev/null 2>&1 || true
    fi
}

pass() {
    local body
    body="$(curl -fsS -m 10 "$AM_URL/api/v2/alerts?active=true&silenced=false&inhibited=false" 2>/dev/null)" || {
        emit "ALERTMANAGER_UNREACHABLE $AM_URL"
        return 0
    }
    local tmp_dir now_f
    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/stell-alert.XXXXXX")" || {
        emit "ALERT_NOTIFY_TMP_ERROR"
        return 0
    }
    now_f="$tmp_dir/now"
    : >"$now_f"
    printf '%s' "$body" | python3 -c '
import sys, json
try:
    alerts = json.load(sys.stdin) or []
except Exception:
    sys.exit(0)
for a in alerts:
    labels = a.get("labels") or {}
    ann = a.get("annotations") or {}
    name = labels.get("alertname", "?")
    node = labels.get("node", labels.get("instance", "?"))
    mount = labels.get("mountpoint", "-")
    sev = labels.get("severity", "?")
    summary = ann.get("summary", "").replace("\n", " ")
    key = "|".join([name, node, mount])
    print("%s\t[%s] %s (%s) %s" % (key, sev.upper(), name, node, summary))
' >"$now_f"

    cut -f1 "$now_f" | sort -u >"$tmp_dir/keys"
    : >"$tmp_dir/prev"
    [ -f "$STATE" ] && sort -u "$STATE" >"$tmp_dir/prev"

    # NEW: present now, absent from the previous snapshot.
    comm -23 "$tmp_dir/keys" "$tmp_dir/prev" | while IFS= read -r key; do
        [ -n "$key" ] || continue
        line="$(grep -F -- "$key	" "$now_f" | head -n1 | cut -f2-)"
        emit "FIRING $line"
    done
    # RESOLVED: present before, gone now.
    comm -13 "$tmp_dir/keys" "$tmp_dir/prev" | while IFS= read -r key; do
        [ -n "$key" ] || continue
        emit "RESOLVED $key"
    done

    mv -f "$tmp_dir/keys" "$STATE" 2>/dev/null || cp -f "$tmp_dir/keys" "$STATE" 2>/dev/null || true
    rm -rf "$tmp_dir"
}

if [ "$LOOP" -gt 0 ]; then
    while true; do pass; sleep "$LOOP"; done
else
    pass
fi
