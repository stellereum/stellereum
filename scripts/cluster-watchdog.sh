#!/usr/bin/env bash
# ==============================================================================
# cluster-watchdog.sh — watch the cluster, alert on trouble, heal what is safe.
#
# WHAT IT WATCHES (each of these actually happened during the deployment
# attempt, and every one of them was INVISIBLE in the node's own logs):
#
#   * a node is DOWN or CRASH-LOOPING (Node B was down and crash-looping at
#     the start of the deployment, unnoticed);
#   * a node is on a DIFFERENT PUBSUB TOPIC (Node C had STELL_SHARDS=0 while
#     the others had 0,1 — a different topic, a different network, zero log
#     evidence);
#   * a node's inode usage is above the threshold (Node C hit 655360/655360
#     inodes: read-only filesystem, silent drop-out of consensus);
#   * the masterchain tip has NOT ADVANCED for N seconds (the cluster sat at
#     285027 in a view-change storm);
#   * a node holds a pile of orphan chunk files (463589 of them on Node C).
#   * a node logged DIVERGENCE (2026-10-22 #288000: B and C finalized the same
#     block hash with different post-state roots — same chain, same height,
#     different state, finalization stalled with zero log evidence before
#     the DIVERGENCE tag existed).
#
# WHAT IT HEALS (and what it NEVER heals):
#   SAFE to auto-heal:
#     - restart a dead service (the unit is enabled and the node is down);
#     - PRUNE the orphan chunks (the sweeper only removes files nothing
#       points at any more).
#   NEVER auto-healed — REPORTED ONLY, because a machine cannot guess the
#   operator's intent and a wrong guess here breaks the chain:
#     - a config drift (a different STELL_SHARDS / topic / chain id / genesis
#       root / timeout / base fee);
#     - a stale consensus lock (clearing it changes the node's safety state:
#       use `stell-sync.sh lockclear <node> --force`);
#     - a node that is behind (re-syncing it is an operator decision).
#     - an execution DIVERGENCE (resyncing the wrong side cements the fork:
#       compare with `stelops diverge`, then resync the minority side).
#
# ALERTING: every alert goes to stdout AND stderr, and the script exits
# non-zero, so a cron/monitoring wrapper can act on it.
#
# Usage:
#   cluster-watchdog.sh [--interval SEC] [--once] [--no-heal] [--json]
#                        [--stall-seconds N] [--state-file PATH]
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STELL_CONF="${STELL_CONF:-$SCRIPT_DIR/cluster-nodes.conf}"
if [ -r "$STELL_CONF" ]; then
    # shellcheck disable=SC1090
    . "$STELL_CONF"
fi

WATCH_INTERVAL="${WATCH_INTERVAL:-60}"
WATCH_ONCE=0
WATCH_HEAL=1
WATCH_JSON=0
WATCH_STATE="${WATCH_STATE:-/tmp/stellereum-watchdog.state}"
WATCH_PROBE_TIMEOUT="${STELL_PROBE_TIMEOUT:-25}"
WATCH_ORPHANS=0          # the orphan count is slow; the healer runs it anyway
HEAL_ORPHAN_THRESHOLD="${HEAL_ORPHAN_THRESHOLD:-50000}"
HEAL_INODE_THRESHOLD="${HEAL_INODE_THRESHOLD:-$INODE_HARD_PCT}"

NODPROBE="${NODPROBE:-$SCRIPT_DIR/lib/nodeprobe.sh}"
PRUNE_SCRIPT="${PRUNE_SCRIPT:-$SCRIPT_DIR/node-prune-cron.sh}"

usage() {
    cat <<EOF
cluster-watchdog.sh — watch the Stellereum cluster, alert on trouble, heal what is safe

USAGE
  cluster-watchdog.sh [options]

OPTIONS
  --interval SEC      seconds between checks (default $WATCH_INTERVAL)
  --once              run one check and exit
  --no-heal           report only; never restart or prune
  --json              machine-readable output (one JSON object per check)
  --stall-seconds N   the masterchain tip must advance within N seconds
                      (default $STALL_SECONDS)
  --state-file PATH   where the tip history is kept (default $WATCH_STATE)
  --help              this text

ALERTS (stdout + stderr, exit code 1)
  * a node is DOWN or CRASH-LOOPING
  * a node is on a different pubsub topic, or its config drifted
  * a node's inode usage is above $INODE_HARD_PCT%
  * the masterchain tip has not advanced for --stall-seconds
  * a node logged DIVERGENCE (execution fork: same hash, different state)

AUTO-HEAL (safe cases only)
  * restart a dead service
  * prune the orphan chunk files
  NEVER: a config drift, a stale consensus lock, a lagging node.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --interval) WATCH_INTERVAL="$2"; shift 2 ;;
        --once) WATCH_ONCE=1; shift ;;
        --no-heal) WATCH_HEAL=0; shift ;;
        --json) WATCH_JSON=1; shift ;;
        --stall-seconds) STALL_SECONDS="$2"; shift 2 ;;
        --state-file) WATCH_STATE="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "cluster-watchdog.sh: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

# --- helpers ----------------------------------------------------------------
log()  {
    if [ "$WATCH_JSON" = "1" ]; then
        echo "[watchdog $(date -u '+%H:%M:%S')] $*" >&2
    else
        echo "[watchdog $(date -u '+%H:%M:%S')] $*"
    fi
}
alert() {
    if [ "$WATCH_JSON" = "1" ]; then
        # keep stdout parseable: the alert goes to stderr only
        echo "[watchdog $(date -u '+%H:%M:%S')] ALERT: $*" >&2
    else
        echo "[watchdog $(date -u '+%H:%M:%S')] ALERT: $*" >&2
        echo "[watchdog $(date -u '+%H:%M:%S')] ALERT: $*"
    fi
}
heal()  {
    if [ "$WATCH_JSON" = "1" ]; then
        echo "[watchdog $(date -u '+%H:%M:%S')] HEAL: $*" >&2
    else
        echo "[watchdog $(date -u '+%H:%M:%S')] HEAL: $*"
    fi
}

node_conf() {
    local n="$1" f="$2" v
    eval "v=\${NODE_${n}_${f}:-}"
    printf '%s' "$v"
}

probe_node() {
    local n="$1"
    local ssh_target opts dir env_file service scope rpc shard_id
    ssh_target="$(node_conf "$n" SSH)"
    opts="$(node_conf "$n" SSH_OPTS)"
    dir="$(node_conf "$n" DIR)"
    env_file="$(node_conf "$n" ENV)"
    service="$(node_conf "$n" SERVICE)"
    scope="$(node_conf "$n" SCOPE)"
    rpc="$(node_conf "$n" RPC)"
    shard_id="$(node_conf "$n" SHARD_ID)"
    [ -r "$NODPROBE" ] || return 1
    local env_prefix
    env_prefix="STELL_PROBE_NODE=$n STELL_PROBE_DIR=$dir STELL_PROBE_ENV_FILE=$env_file"
    env_prefix="$env_prefix STELL_PROBE_SERVICE=$service STELL_PROBE_SERVICE_SCOPE=$scope"
    env_prefix="$env_prefix STELL_PROBE_RPC=$rpc STELL_PROBE_SHARD_ID=$shard_id"
    env_prefix="$env_prefix STELL_PROBE_ORPHANS=$WATCH_ORPHANS"
    if [ -z "$ssh_target" ]; then
        env $env_prefix sh "$NODPROBE" 2>/dev/null || true
    else
        # shellcheck disable=SC2086
        timeout "$WATCH_PROBE_TIMEOUT" ssh -o BatchMode=yes -o ConnectTimeout=8 $opts "$ssh_target" \
            "$env_prefix sh -s" < "$NODPROBE" 2>/dev/null || true
    fi
}

# run a command on a node (local or over ssh)
node_run() {
    local n="$1"; shift
    local ssh_target opts
    ssh_target="$(node_conf "$n" SSH)"
    opts="$(node_conf "$n" SSH_OPTS)"
    if [ -z "$ssh_target" ]; then
        "$@" 2>&1
    else
        # shellcheck disable=SC2086
        timeout 300 ssh -o BatchMode=yes -o ConnectTimeout=8 $opts "$ssh_target" "$@" 2>&1
    fi
}

# --- the check --------------------------------------------------------------
run_check() {
    local n out state tip ipct orph topic expect_topic exitcode restarts
    local problems=0
    local json_first=1
    local max_tip=0
    local ref_topic="" ref_shards="" ref_chainid=""

    if [ "$WATCH_JSON" = "1" ]; then
        echo "{\"ts\":\"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\",\"heal\":$([ "$WATCH_HEAL" = "1" ] && echo true || echo false),\"nodes\":["
    else
        echo "================================================================================"
        echo " CLUSTER WATCHDOG  ($(date -u '+%Y-%m-%dT%H:%M:%SZ'))  heal=$([ "$WATCH_HEAL" = "1" ] && echo on || echo off)"
        echo "================================================================================"
    fi

    for n in $STELL_NODES; do
        out="$(probe_node "$n")"
        if [ -z "$out" ]; then
            alert "node $n is UNREACHABLE (no answer from the probe)"
            problems=$((problems + 1))
            continue
        fi
        f() { printf '%s' "$out" | sed -n "s/^$1=//p" | head -1; }

        state="$(f service_state)"
        tip="$(f tip)"
        ipct="$(f inode_pct)"
        orph="$(f chunk_orphans)"
        topic="$(f topic)"
        expect_topic="$(f expected_topic)"
        exitcode="$(f service_exit_code)"
        restarts="$(f service_restarts)"
        local shards chainid basefee epoch
        shards="$(f env_STELL_SHARDS)"
        chainid="$(f chain_id)"
        basefee="$(f base_fee)"
        epoch="$(f epoch)"

        if [ "$WATCH_JSON" = "1" ]; then
            [ "$json_first" = "0" ] && printf ',\n'
            json_first=0
            printf '    {"node":"%s","state":"%s","tip":"%s","inode_pct":"%s","orphans":"%s","topic":"%s","expected_topic":"%s","exit_code":"%s","restarts":"%s"}\n' \
                "$n" "$state" "${tip:-?}" "${ipct:-?}" "${orph:-?}" "${topic:-?}" "${expect_topic:-?}" \
                "${exitcode:-?}" "${restarts:-?}"
        else
            printf "  %-4s %-9s tip=%-10s inodes=%-5s orphans=%-9s topic=%s\n" \
                "$n" "$state" "${tip:-?}" "${ipct:-?}%" "${orph:-?}" "${topic:-?}"
        fi

        # --- DOWN / CRASH-LOOPING ------------------------------------------
        case "$state" in
            active)
                if [ "$exitcode" = "203" ]; then
                    alert "node $n is CRASH-LOOPING on 203/EXEC (the binary is missing or not executable — a 'cargo clean' under the live node does this)"
                    problems=$((problems + 1))
                elif [ -n "$restarts" ] && [ "$restarts" -ge 3 ] 2>/dev/null; then
                    alert "node $n is CRASH-LOOPING ($restarts restarts of $node_conf "$n" SERVICE)"
                    problems=$((problems + 1))
                fi
                ;;
            inactive|failed|deactivating)
                alert "node $n is DOWN (service state: $state)"
                problems=$((problems + 1))
                # SAFE auto-heal: restart the unit. The unit is `Restart=always`,
                # so systemd is already trying; a manual restart resets a
                # failed unit and clears the start-limit.
                if [ "$WATCH_HEAL" = "1" ]; then
                    local scope svc
                    scope="$(node_conf "$n" SCOPE)"
                    svc="$(node_conf "$n" SERVICE)"
                    if [ "$scope" = "user" ]; then
                        heal "restarting the user unit $svc on node $n"
                        node_run "$n" "systemctl --user restart $svc" >/dev/null 2>&1
                    else
                        heal "restarting $svc on node $n"
                        node_run "$n" "systemctl restart $svc" >/dev/null 2>&1
                    fi
                fi
                ;;
            activating)
                alert "node $n is still starting"
                ;;
            *)
                alert "node $n is in state '$state'"
                problems=$((problems + 1))
                ;;
        esac

        # --- a different pubsub topic (a config drift: NEVER auto-healed) ---
        if [ "$topic" != "?" ] && [ "$expect_topic" != "?" ] && [ "$topic" != "$expect_topic" ]; then
            alert "node $n is on pubsub topic '$topic' but should be on '$expect_topic' — it is ISOLATED from the network. Fix the config (this is NOT auto-healed)"
            problems=$((problems + 1))
        fi
        if [ -n "$shards" ] && [ -n "$ref_shards" ] && [ "$shards" != "$ref_shards" ]; then
            alert "node $n has STELL_SHARDS=$shards but the cluster runs $ref_shards — a different shard set means a different topic. Fix the config (this is NOT auto-healed)"
            problems=$((problems + 1))
        fi
        [ -z "$ref_shards" ] && ref_shards="$shards"

        if [ -n "$chainid" ] && [ "$chainid" != "?" ] && [ -n "$ref_chainid" ] && [ "$chainid" != "$ref_chainid" ]; then
            alert "node $n reports chain id $chainid but the cluster runs $ref_chainid — a different chain. Fix the config (this is NOT auto-healed)"
            problems=$((problems + 1))
        fi
        [ -z "$ref_chainid" ] && ref_chainid="$chainid"

        # --- the inodes ------------------------------------------------------
        if [ -n "$ipct" ] && [ "$ipct" != "?" ] && [ "$ipct" -ge "$INODE_HARD_PCT" ] 2>/dev/null; then
            alert "node $n inode usage is ${ipct}% (>= ${INODE_HARD_PCT}%) — the filesystem goes read-only at 100% and the node drops out of consensus silently"
            problems=$((problems + 1))
            # SAFE auto-heal: prune the orphan chunks.
            if [ "$WATCH_HEAL" = "1" ]; then
                heal "pruning the orphan chunks on node $n"
                node_run "$n" "sh $PRUNE_SCRIPT --dir $(node_conf "$n" DIR)" >/dev/null 2>&1
            fi
        elif [ -n "$ipct" ] && [ "$ipct" != "?" ] && [ "$ipct" -ge "$INODE_WARN_PCT" ] 2>/dev/null; then
            alert "node $n inode usage is ${ipct}% (>= ${INODE_WARN_PCT}%)"
        fi

        # --- the orphan chunks ----------------------------------------------
        if [ -n "$orph" ] && [ "$orph" != "?" ] && [ "$orph" != "skipped" ] && [ "$orph" -ge "$HEAL_ORPHAN_THRESHOLD" ] 2>/dev/null; then
            alert "node $n holds $orph orphan chunk files (>= ${HEAL_ORPHAN_THRESHOLD})"
            if [ "$WATCH_HEAL" = "1" ]; then
                heal "pruning the orphan chunks on node $n"
                node_run "$n" "sh $PRUNE_SCRIPT --dir $(node_conf "$n" DIR)" >/dev/null 2>&1
            fi
        fi

        # --- the tip ---------------------------------------------------------
        if [ -n "$tip" ] && [ "$tip" != "?" ] && [ "$tip" -gt "$max_tip" ] 2>/dev/null; then
            max_tip="$tip"
        fi

    # --- execution divergence (2026-10-22 #288000: same finalized hash,
    #     different post-state roots). The node logs a greppable DIVERGENCE
    #     line every time it refuses a proposal over a state-root
    #     mismatch; ANY hit means the chain is forked at the execution
    #     layer even if block hashes still agree. REPORTED ONLY: picking
    #     the canonical side needs `stelops diverge` + an operator.
    #     The DIVERGENCE line always carries their_root=<hex> our_root=<hex>
    #     on the SAME journal line (see runtime.rs), but the pattern below
    #     also matches a bare their_root.*our_root line so a future log
    #     format that drops the tag is still paged on.
    local svc scope div_pat div
    div_pat='DIVERGENCE|their_root.*our_root'
    svc="$(node_conf "$n" SERVICE)"
    scope="$(node_conf "$n" SCOPE)"
    if [ "$scope" = "user" ]; then
        div="$(node_run "$n" journalctl --user -u "$svc" --since "10 minutes ago" --no-pager 2>/dev/null | grep -c -E "$div_pat" 2>/dev/null || true)"
    else
        div="$(node_run "$n" journalctl -u "$svc" --since "10 minutes ago" --no-pager 2>/dev/null | grep -c -E "$div_pat" 2>/dev/null || true)"
    fi
        case "$div" in
            ''|*[!0-9]*) div=0 ;;
        esac
        if [ "$div" -gt 0 ] 2>/dev/null; then
            alert "node $n logged DIVERGENCE ${div}x in the last 10 minutes — same finalized hash but different post-state roots (execution fork). Compare with 'stelops diverge' and resync the minority side from a canonical snapshot (this is NOT auto-healed)"
            problems=$((problems + 1))
        fi
    done

    # --- the masterchain tip: has it advanced? ------------------------------
    local last_tip last_time now_t
    now_t=$(date +%s)
    last_tip=0; last_time=$now_t
    if [ -r "$WATCH_STATE" ]; then
        # the state file: "<tip> <timestamp>"
        read -r last_tip last_time < "$WATCH_STATE" 2>/dev/null || true
    fi
    [ -z "$last_tip" ] && last_tip=0
    [ -z "$last_time" ] && last_time=$now_t

    local stalled=0
    if [ "$max_tip" -gt 0 ]; then
        if [ "$max_tip" -gt "$last_tip" ]; then
            echo "$max_tip $now_t" > "$WATCH_STATE" 2>/dev/null || true
            log "masterchain tip: $max_tip (advanced)"
        else
            local age=$(( now_t - last_time ))
            if [ "$age" -ge "$STALL_SECONDS" ]; then
                alert "the masterchain tip has NOT advanced for ${age}s (still $max_tip) — the chain is STALLED (a view-change storm or a split validator set)"
                problems=$((problems + 1))
                stalled=1
            else
                log "masterchain tip: $max_tip (unchanged for ${age}s)"
            fi
        fi
    else
        alert "no node reports a masterchain tip — the whole cluster is unreachable"
        problems=$((problems + 1))
    fi

    if [ "$WATCH_JSON" = "1" ]; then
        echo "  ],\"problems\":$problems,\"max_tip\":${max_tip:-0},\"stalled\":$([ "${stalled:-0}" = "1" ] && echo true || echo false)}"
    else
        echo "================================================================================"
    fi
    if [ "$problems" -eq 0 ]; then
        log "all clear"
        return 0
    fi
    log "$problems problem(s) detected"
    return 1
}

# --- the loop ---------------------------------------------------------------
if [ "$WATCH_ONCE" = "1" ]; then
    run_check
    exit $?
fi

log "watching $STELL_NODES every ${WATCH_INTERVAL}s (state: $WATCH_STATE). Ctrl-C to stop."
while true; do
    run_check || true
    sleep "$WATCH_INTERVAL"
done
