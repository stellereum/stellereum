#!/usr/bin/env bash
# ==============================================================================
# rolling-deploy.sh — two-phase, one-node-at-a-time binary deploy.
#
# WHY TWO PHASES
# At the live tempo (STELL_MIN_BLOCK_MS=400) a validator is jailed after
# DOWNTIME_MISS_THRESHOLD = 42 consecutive missed heights: 42 x 400 ms = 16.8 s.
# Streaming a 43 MB binary to a 1-vCPU validator stalls consensus long enough to
# miss that budget. The transfer therefore happens in `stage`, while the old
# binary is still running and voting:
#
#   stage <binary> [nodes...]
#       copy to <node-dir>/stellereum.new.next with nice/ionice, verify SHA-256
#       against the local file, write <node-dir>/stellereum.new.sha256.
#       The running <node-dir>/stellereum is NOT touched.
#
#   activate [nodes...]
#       per node, in sequence: preflight the staged digest, timestamp T0,
#       cp stellereum -> stellereum.prev, mv stellereum.new.next -> stellereum,
#       systemctl restart, wait for active, then wait for the local RPC to be
#       within 5 blocks of the public tip. Print the measured downtime, warn
#       above 15 s, report a jail with release_height + cold-key unjail command,
#       and re-check stell_getValidators (>=3 validators, fragile=false) before
#       touching the next node. Any failed check ABORTS the rest of the rollout.
#
# The script never reads env files, never prints key material, and never
# auto-unjails unless both --unjail-on-jail and --withdrawal-key-file are given.
#
# Usage:
#   rolling-deploy.sh stage <binary> [nodes...] [--dry-run]
#   rolling-deploy.sh activate [nodes...] [--dry-run]
#   rolling-deploy.sh --dry-run [--nodes "A"]
#
# Flags:
#   --dry-run                  print the plan; touch nothing
#   --nodes "A C"              node subset (default: STELL_NODES from the conf)
#   --public-rpc URL           reference tip / cluster RPC
#                              (default $STELL_PUBLIC_RPC, https://rpc.stellereum.org)
#   --validator <64-hex>       validator id for a single-node run (no auto-detect)
#   --unjail-on-jail           explicitly auto-unjail a jailed validator
#                              (requires --withdrawal-key-file; off by default)
#   --withdrawal-key-file PATH COLD withdrawal key path (never read or printed)
#   --canary                   canary mode for activate: activate ONLY the first
#                              node, soak --canary-soak-secs, auto-rollback on
#                              failure, and leave remaining nodes untouched
#   --canary-soak-secs N       canary soak window in seconds (default: 30)
#   -h, --help                 this text
#
# Environment (all optional):
#   STELL_CONF                     cluster conf (default scripts/cluster-nodes.conf)
#   STELL_PUBLIC_RPC               default reference RPC
#   STELL_MIN_BLOCK_MS             live tempo used for the jail arithmetic (400)
#   STELL_ROLL_DEPLOY_CATCHUP_SECS catch-up poll bound after restart (300)
#   STELL_CLUSTER_SIZE             expected validator count for the 4/4 line (4)
#
# Exit codes: 0 ok, 1 rollout aborted, 64 usage/configuration error.
# No --allow-root: ssh as root, or run as the service user for a --user unit.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
CONF="${STELL_CONF:-$SCRIPT_DIR/cluster-nodes.conf}"

JAIL_MISSES=42
# The jail budget is 42 consecutive missed heights; its length in SECONDS is
# whatever the fleet's block tempo is. Take the operator override first, then
# the value the cluster conf expects (the preflight enforces it), and only
# then the historical 400 ms default.
BLOCK_MS="${STELL_MIN_BLOCK_MS:-${EXPECT_STELL_MIN_BLOCK_MS:-400}}"
# Warn at 90% of the real budget instead of a hardcoded 15 s.
DOWNTIME_WARN_MS=$((JAIL_MISSES * BLOCK_MS * 9 / 10))
CATCHUP_SECS="${STELL_ROLL_DEPLOY_CATCHUP_SECS:-300}"
CLUSTER_SIZE="${STELL_CLUSTER_SIZE:-4}"
PUBLIC_RPC="${STELL_PUBLIC_RPC:-https://rpc.stellereum.org}"

COMMAND=""
BINARY=""
NODE_SPEC=""
DRY_RUN=0
CANARY=0
CANARY_SOAK_SECS=30
VALIDATOR=""
UNJAIL_ON_JAIL=0
WITHDRAWAL_KEY_FILE=""
POSITIONAL=()
NODES=()
BASELINE_COUNT=""
PUBLIC_DOWN_WARNED=0

note() { printf '[rolling-deploy] %s\n' "$*"; }
warn() { printf '[rolling-deploy] WARN: %s\n' "$*" >&2; }
die()  { printf '[rolling-deploy] ERROR: %s\n' "$*" >&2; exit 64; }

usage() { sed -n '2,57p' "$0" | sed 's/^# \{0,1\}//'; }

now_ms() {
    local n
    n="$(date +%s%3N 2>/dev/null || true)"
    case "$n" in
        ''|*[!0-9]*) printf '%s' "$(( $(date +%s) * 1000 ))" ;;
        *) printf '%s' "$n" ;;
    esac
}

fmt_ms() {
    local ms="$1"
    printf '%d.%03ds' "$((ms / 1000))" "$((ms % 1000))"
}

fmt_s1() {
    local ms="$1"
    printf '%d.%01ds' "$((ms / 1000))" "$((ms % 1000 / 100))"
}

jail_budget_text() {
    local ms=$((JAIL_MISSES * BLOCK_MS))
    printf '%d misses x %d ms = %d.%01d s' \
        "$JAIL_MISSES" "$BLOCK_MS" "$((ms / 1000))" "$((ms % 1000 / 100))"
}

node_attr() {
    local node="$1"
    local attr="$2"
    local var="NODE_${node}_${attr}"
    printf '%s' "${!var:-}"
}

node_validator() {
    local node="$1" v
    v="$(node_attr "$node" VALIDATOR)"
    [ -n "$v" ] || v="$(node_attr "$node" VALIDATOR_ID)"
    printf '%s' "$v"
}

read_nodes() {
    local spec="$1"
    NODES=()
    spec="${spec//,/ }"
    if [ -n "$spec" ]; then
        read -r -a NODES <<<"$spec"
    else
        read -r -a NODES <<<"${STELL_NODES:-A B C D}"
    fi
    [ "${#NODES[@]}" -gt 0 ] || die "no nodes selected"
    local n
    for n in "${NODES[@]}"; do
        [[ "$n" =~ ^[A-Za-z0-9_]+$ ]] || die "invalid node name: $n"
        [ -n "$(node_attr "$n" DIR)" ] \
            || die "node $n is not defined in $CONF (NODE_${n}_DIR)"
    done
}

# Run a shell command on a node. Empty NODE_<X>_SSH means "this host" (nodeB).
nrun() {
    local node="$1" cmd="$2" host opts
    host="$(node_attr "$node" SSH)"
    opts="$(node_attr "$node" SSH_OPTS)"
    if [ -n "$host" ]; then
        local -a ssh_opts=()
        if [ -n "$opts" ]; then
            read -r -a ssh_opts <<<"$opts"
        fi
        # A 1-vCPU node can accept the TCP connection and then stall before the
        # command runs; without a hard cap the probe hangs for minutes and the
        # measured "downtime" becomes an SSH artifact (observed: 243 s while the
        # node was actually voting). Kill the probe instead of trusting it.
        timeout 30 ssh -o BatchMode=yes -o ConnectTimeout=10 \
            -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
            "${ssh_opts[@]+"${ssh_opts[@]}"}" "$host" "$cmd"
    else
        timeout 30 bash -c "$cmd"
    fi
}

sysctl_for() {
    local node="$1" scope
    scope="$(node_attr "$node" SCOPE)"
    if [ "$scope" = "user" ]; then
        printf 'systemctl --user'
    else
        printf 'systemctl'
    fi
}

# Run a command that legitimately BLOCKS longer than a probe: `systemctl
# restart` waits for the stop half, and a busy node drains for up to
# TimeoutStopSec (90 s on the live fleet). The 30 s probe cap would kill such a
# command while systemd kept going, and the script then reported a false
# "swap/restart failed" (observed on nodeC: the node came up on the new binary
# with no operator action). Probes keep the short cap; lifecycle commands get
# the long one.
nrun_long() {
    local node="$1" cmd="$2" host opts
    host="$(node_attr "$node" SSH)"
    opts="$(node_attr "$node" SSH_OPTS)"
    if [ -n "$host" ]; then
        local -a ssh_opts=()
        if [ -n "$opts" ]; then
            read -r -a ssh_opts <<<"$opts"
        fi
        timeout 330 ssh -o BatchMode=yes -o ConnectTimeout=10 \
            -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
            "${ssh_opts[@]+"${ssh_opts[@]}"}" "$host" "$cmd"
    else
        timeout 330 bash -c "$cmd"
    fi
}

# The per-node liveness guard restarts a stopped unit within 60 s. A rolling
# activate that stops the guard unit first and restarts it afterwards is the
# only way a restart stays a SINGLE instance: with the guard live, a stop/start
# can race and leave two processes on one sled store, which corrupts the safety
# record (live incident 2026-11-23, nodeC).
guard_unit() {
    printf '%s' "${STELL_ROLL_GUARD_UNIT:-stell-node-guard.timer}"
}

rpc_cmd() {
    local url="$1" method="$2" params="$3" payload
    payload="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}"
    printf 'curl -sS -m 8 -X POST %s -H %s -d %s' \
        "$(printf '%q' "$url")" \
        "$(printf '%q' "content-type: application/json")" \
        "$(printf '%q' "$payload")"
}

json_height() {
    local body="$1" result
    result="$(printf '%s' "$body" | jq -r '.result // empty' 2>/dev/null || true)"
    if [[ "$result" =~ ^0[xX][0-9a-fA-F]+$ ]]; then
        printf '%d' "$((16#${result:2}))"
    elif [[ "$result" =~ ^[0-9]+$ ]]; then
        printf '%d' "$((10#$result))"
    else
        return 1
    fi
}

rpc_height() {
    local url="$1" body
    body="$(curl -sS -m 8 -X POST "$url" -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}' 2>/dev/null || true)"
    json_height "$body"
}

node_height() {
    local node="$1" url cmd body
    url="$(node_attr "$node" RPC)"
    [ -n "$url" ] || return 1
    cmd="$(rpc_cmd "$url" stell_blockNumber '[]')"
    body="$(nrun "$node" "$cmd" 2>/dev/null || true)"
    json_height "$body"
}

remote_sha() {
    local node="$1" path="$2" out q_path
    q_path="$(printf '%q' "$path")"
    out="$(nrun "$node" "sha256sum $q_path 2>/dev/null | cut -d' ' -f1" || true)"
    [ "${#out}" -eq 64 ] || return 1
    printf '%s' "$out"
}

public_tip() {
    local skip="$1" tip node
    tip="$(rpc_height "$PUBLIC_RPC" || true)"
    if [ -n "$tip" ]; then
        printf '%s' "$tip"
        return 0
    fi
    if [ "$PUBLIC_DOWN_WARNED" -eq 0 ]; then
        PUBLIC_DOWN_WARNED=1
        warn "public RPC $PUBLIC_RPC is not answering; using a peer's local tip as reference"
    fi
    for node in "${NODES[@]}"; do
        [ "$node" = "$skip" ] && continue
        tip="$(node_height "$node" || true)"
        if [ -n "$tip" ]; then
            printf '%s' "$tip"
            return 0
        fi
    done
    return 1
}

cluster_json_ok() {
    printf '%s' "$1" | jq -e \
        '(.result.validators // .validators) | type == "array" and length > 0' \
        >/dev/null 2>&1
}

fetch_cluster_json() {
    local attempt node url cmd json
    for attempt in 1 2 3 4 5 6; do
        json="$(curl -sS -m 8 -X POST "$PUBLIC_RPC" -H 'content-type: application/json' \
            -d '{"jsonrpc":"2.0","id":1,"method":"stell_getValidators","params":[]}' 2>/dev/null || true)"
        if cluster_json_ok "$json"; then
            printf '%s' "$json"
            return 0
        fi
        for node in "${NODES[@]}"; do
            url="$(node_attr "$node" RPC)"
            [ -n "$url" ] || continue
            cmd="$(rpc_cmd "$url" stell_getValidators '[]')"
            json="$(nrun "$node" "$cmd" 2>/dev/null || true)"
            if cluster_json_ok "$json"; then
                printf '%s' "$json"
                return 0
            fi
        done
        sleep 2
    done
    return 1
}

cluster_check() {
    local json count fragile total
    if ! json="$(fetch_cluster_json)"; then
        warn "cannot read stell_getValidators from any endpoint; cluster state UNKNOWN"
        return 1
    fi
    count="$(printf '%s' "$json" | jq -r '(.result.validators // .validators) | length')"
    [[ "$count" =~ ^[0-9]+$ ]] || { warn "invalid validator count from RPC: $count"; return 1; }
    fragile="$(printf '%s' "$json" | jq -r '(.result.fragile // .fragile // false) | tostring')"
    total="$(printf '%s' "$json" | jq -r '(.result.total_power // .total_power // "?") | tostring')"
    note "cluster: ${count}/${CLUSTER_SIZE} validators, total_power=${total}, fragile=${fragile}"
    if [ "$fragile" = "true" ]; then
        warn "cluster reports fragile=true; refusing to continue the rollout"
        return 1
    fi
    if [ "$count" -lt 3 ]; then
        warn "validator count ${count} < 3; refusing to continue the rollout"
        return 1
    fi
    if [ -n "$BASELINE_COUNT" ] && [ "$count" -lt "$BASELINE_COUNT" ]; then
        warn "validator count dropped from ${BASELINE_COUNT} to ${count}"
    fi
    if [ "$count" -lt "$CLUSTER_SIZE" ]; then
        warn "cluster is running degraded at ${count}/${CLUSTER_SIZE}"
    fi
    return 0
}

show_plan() {
    local node dir ssh unit scope rpc validator digest_note="" idx=0
    note "DRY RUN — nothing is copied, restarted, or written."
    note "jail budget: $(jail_budget_text); warn above $(fmt_s1 "$DOWNTIME_WARN_MS")"
    note "public RPC: $PUBLIC_RPC"
    if [ "$CANARY" -eq 1 ]; then
        note "canary mode: activate ONLY first node (${NODES[0]}), soak ${CANARY_SOAK_SECS}s (height advancing + not jailed + cluster healthy), auto-rollback on fail"
    fi
    if [ -n "$BINARY" ] && [ -f "$BINARY" ]; then
        digest_note="$(sha256sum "$BINARY" 2>/dev/null | cut -d' ' -f1 || true)"
    fi
    for node in "${NODES[@]}"; do
        dir="$(node_attr "$node" DIR)"
        ssh="$(node_attr "$node" SSH)"; [ -n "$ssh" ] || ssh="local"
        unit="$(node_attr "$node" SERVICE)"
        scope="$(node_attr "$node" SCOPE)"; scope="${scope:-system}"
        rpc="$(node_attr "$node" RPC)"
        validator="$(node_validator "$node")"; [ -n "$validator" ] || validator="${VALIDATOR:-auto/unknown}"
        note "node $node: target=$ssh dir=$dir unit=$unit scope=$scope rpc=$rpc validator=$validator"
        if [ -z "$COMMAND" ] || [ "$COMMAND" = "stage" ]; then
            note "  stage: nice -n 19 ionice -c3 copy ${BINARY:-<binary>} -> $dir/stellereum.new.next"
            note "         sha256 ${digest_note:-<computed at stage time>} -> $dir/stellereum.new.sha256"
            note "         running $dir/stellereum is not touched"
        fi
        if [ -z "$COMMAND" ] || [ "$COMMAND" = "activate" ]; then
            if [ "$CANARY" -eq 1 ] && [ "$idx" -gt 0 ]; then
                note "  activate: SKIPPED (canary mode touches only first node ${NODES[0]})"
            else
                note "  activate: sha256 preflight -> cp -f stellereum stellereum.prev -> mv .new.next stellereum"
                note "            pause $(guard_unit), then $([ "$scope" = user ] && printf 'systemctl --user' || printf 'systemctl') restart $unit, then resume the guard"
                note "            (a live guard can start a SECOND instance on the same store)"
                note "            wait is-active <=120 s, then local height within 5 of $PUBLIC_RPC"
                note "            warn if downtime >15 s; abort if <3 validators or fragile=true"
                if [ "$CANARY" -eq 1 ]; then
                    note "  canary:   soak ${CANARY_SOAK_SECS}s checking local RPC height advancing + not jailed + cluster healthy"
                    note "            auto-rollback on fail: pause $(guard_unit), mv -f stellereum.prev stellereum, $([ "$scope" = user ] && printf 'systemctl --user' || printf 'systemctl') restart $unit, resume guard, ABORT"
                fi
            fi
        fi
        idx=$((idx + 1))
    done
    note "DRY RUN complete; no node was contacted."
}

do_stage() {
    local binary="$1" digest node dir tmp final sum want remote_ionice

    BINARY="$binary"
    if [ "$DRY_RUN" -eq 1 ]; then
        if [ -z "$binary" ]; then
            warn "no binary given (dry run prints the plan without a digest)"
        elif [ ! -f "$binary" ]; then
            warn "binary $binary does not exist (dry run continues without a digest)"
        fi
        show_plan
        return 0
    fi

    [ -n "$binary" ] || die "stage needs a binary path: stage <binary> [nodes...]"
    [ -f "$binary" ] || die "binary not found: $binary"
    [ -r "$binary" ] || die "binary not readable: $binary"

    digest="$(sha256sum "$binary" | cut -d' ' -f1)"
    [ "${#digest}" -eq 64 ] || die "could not compute sha256 of $binary"
    note "local binary: $binary"
    note "sha256: $digest"
    note "jail budget: $(jail_budget_text)"

    for node in "${NODES[@]}"; do
        dir="$(node_attr "$node" DIR)"
        final="$dir/stellereum.new.next"
        tmp="$dir/.stellereum.new.next.tmp.$$"
        local q_dir q_tmp q_final q_digest q_shafile
        q_dir="$(printf '%q' "$dir")"
        q_tmp="$(printf '%q' "$tmp")"
        q_final="$(printf '%q' "$final")"
        q_digest="$(printf '%q' "$digest")"
        q_shafile="$(printf '%q' "$dir/stellereum.new.sha256")"

        note "[$node] staging -> $final"
        nrun "$node" "test -d $q_dir" || die "[$node] node dir does not exist: $dir"

        if nrun "$node" "command -v ionice >/dev/null 2>&1"; then
            remote_ionice="nice -n 19 ionice -c3"
        else
            warn "[$node] ionice is absent; falling back to nice -n 19 only"
            remote_ionice="nice -n 19"
        fi

        # Stream while the old binary keeps running. The idle-class copy yields
        # to the consensus thread; the bytes go to a temp name, never to
        # <dir>/stellereum.
        if ! nrun "$node" "$remote_ionice cat > $q_tmp" <"$binary"; then
            nrun "$node" "rm -f $q_tmp" || true
            die "[$node] copy failed"
        fi

        if ! sum="$(remote_sha "$node" "$tmp")"; then
            nrun "$node" "rm -f $q_tmp" || true
            die "[$node] could not read the staged digest"
        fi
        if [ "$sum" != "$digest" ]; then
            nrun "$node" "rm -f $q_tmp" || true
            die "[$node] staged sha256 mismatch: local=$digest remote=$sum"
        fi

        if ! nrun "$node" "chmod 0755 $q_tmp && mv -f $q_tmp $q_final && printf '%s\n' $q_digest > $q_shafile"; then
            nrun "$node" "rm -f $q_tmp" || true
            die "[$node] could not install the staged binary"
        fi
        want="$(nrun "$node" "cat $q_shafile")"
        [ "$want" = "$digest" ] || die "[$node] staged digest file is inconsistent"
        note "[$node] staged and verified; running binary untouched"
    done
    note "stage complete; activate now needs only a rename + restart inside the $(jail_budget_text) budget"
}

report_jail() {
    local node="$1" dir="$2" vid="$3" json="$4" release height blocks_left eta_ms eta_s
    release="$(printf '%s' "$json" | jq -r '.result.release_height // .release_height // empty')"
    height="$(node_height "$node" || true)"
    case "$height" in
        ''|*[!0-9]*) height="" ;;
    esac
    printf '\n'
    printf '%s\n' "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    printf '[rolling-deploy] JAILED: validator %s on node %s\n' "$vid" "$node"
    case "$release" in
        ''|null) printf '[rolling-deploy] release_height: unknown (RPC omitted it)\n' ;;
        *[!0-9]*)
            printf '[rolling-deploy] release_height = %s (non-numeric; verify with stell_getValidatorStatus)\n' "$release"
            ;;
        *)
            printf '[rolling-deploy] release_height = %s\n' "$release"
            if [ -n "$height" ] && [ "$height" -lt "$release" ]; then
                blocks_left=$((release - height))
                eta_ms=$((blocks_left * BLOCK_MS))
                eta_s=$((eta_ms / 1000))
                printf '[rolling-deploy] now at %s, %s blocks left => ETA ~%d min %02d s at %d ms/block\n' \
                    "$height" "$blocks_left" "$((eta_s / 60))" "$((eta_s % 60))" "$BLOCK_MS"
            else
                printf '[rolling-deploy] release height already reached; unjail is eligible now\n'
            fi
            ;;
    esac
    printf '%s\n' "The jail needs the COLD withdrawal key; this script will not use a hot key."
    printf '[rolling-deploy] unjail command (run on %s):\n' "$node"
    printf '  stellereum validator unjail --validator-id %s --withdrawal-key-file %s\n' \
        "$vid" "${WITHDRAWAL_KEY_FILE:-<COLD_WITHDRAWAL_KEY_FILE>}"

    local withdrawal
    withdrawal="$(printf '%s' "$json" | jq -r '.result.withdrawal_address // .withdrawal_address // empty')"
    if [ -z "$withdrawal" ] || [ "$withdrawal" = "null" ]; then
        printf '%s\n' "withdrawal_address is null: claim a cold address first, then unjail."
        printf '  stellereum validator claim-withdrawal --validator-id %s --voting-key-file <HOT_VOTING_KEY> --withdrawal-key-file %s\n' \
            "$vid" "${WITHDRAWAL_KEY_FILE:-<COLD_WITHDRAWAL_KEY_FILE>}"
    fi
    printf '%s\n' "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

    if [ "$UNJAIL_ON_JAIL" -eq 0 ]; then
        note "auto-unjail is off (pass --unjail-on-jail and --withdrawal-key-file to arm it)"
        return 0
    fi
    if [ -z "$WITHDRAWAL_KEY_FILE" ]; then
        warn "refusing auto-unjail: --unjail-on-jail needs --withdrawal-key-file"
        return 0
    fi
    if [ -z "$withdrawal" ] || [ "$withdrawal" = "null" ]; then
        warn "refusing auto-unjail: the validator has no withdrawal_address yet"
        return 0
    fi
    note "[$node] auto-unjailing as ordered (cold key path: $WITHDRAWAL_KEY_FILE)"
    local q_dir q_vid q_key
    q_dir="$(printf '%q' "$dir")"
    q_vid="$(printf '%q' "$vid")"
    q_key="$(printf '%q' "$WITHDRAWAL_KEY_FILE")"
    if ! nrun "$node" "cd $q_dir && ./stellereum validator unjail --validator-id $q_vid --withdrawal-key-file $q_key"; then
        warn "[$node] auto-unjail command failed; unjail manually"
        return 0
    fi
    local after
    after="$(nrun "$node" "$(rpc_cmd "$(node_attr "$node" RPC)" stell_getValidatorStatus "{\"validator\":\"$vid\"}")" 2>/dev/null || true)"
    note "[$node] jailed after unjail: $(printf '%s' "$after" | jq -r '.result.jailed // .jailed // "unknown"' 2>/dev/null || printf 'unknown')"
}

check_validator() {
    local node="$1"
    local dir="$2"
    local vid="$3"
    local json jailed known
    [ -n "$vid" ] || { note "[$node] no validator id in $CONF; pass --validator <hex> to check jail state"; return 0; }
    json="$(nrun "$node" "$(rpc_cmd "$(node_attr "$node" RPC)" stell_getValidatorStatus "{\"validator\":\"$vid\"}")" 2>/dev/null || true)"
    if [ -z "$json" ] || printf '%s' "$json" | grep -q '"error"'; then
        warn "[$node] stell_getValidatorStatus failed; jail state UNKNOWN"
        return 0
    fi
    known="$(printf '%s' "$json" | jq -r '.result.known // .known // "false"' 2>/dev/null || printf 'false')"
    if [ "$known" != "true" ]; then
        warn "[$node] validator $vid has no staking record on this node"
        return 0
    fi
    jailed="$(printf '%s' "$json" | jq -r '.result.jailed // .jailed // "false"' 2>/dev/null || printf 'false')"
    if [ "$jailed" = "true" ]; then
        report_jail "$node" "$dir" "$vid" "$json"
        return 1
    fi
    note "[$node] validator $vid is not jailed"
    return 0
}

activate_one() {
    local node="$1" dir unit sysctl rpc expected actual t0 t1 ms
    local start_h tip local_h active=0 caught=0 waited=0 deadline vid fail=0
    local q_dir q_unit q_guard q_next q_shafile

    dir="$(node_attr "$node" DIR)"
    unit="$(node_attr "$node" SERVICE)"
    rpc="$(node_attr "$node" RPC)"
    sysctl="$(sysctl_for "$node")"
    [ -n "$unit" ] || die "[$node] NODE_${node}_SERVICE is empty"
    [ -n "$rpc" ] || die "[$node] NODE_${node}_RPC is empty"

    q_dir="$(printf '%q' "$dir")"
    q_unit="$(printf '%q' "$unit")"
    q_next="$(printf '%q' "$dir/stellereum.new.next")"
    q_shafile="$(printf '%q' "$dir/stellereum.new.sha256")"

    # --- 1. preflight: only the staged, verified bytes may be activated ------
    note "[$node] preflight: $dir/stellereum.new.next"
    nrun "$node" "test -f $q_next" \
        || die "[$node] no staged binary at $dir/stellereum.new.next (run stage first)"
    nrun "$node" "test ! -L $q_next" \
        || die "[$node] staged candidate is a symlink; refusing"
    expected="$(nrun "$node" "cat $q_shafile 2>/dev/null" || true)"
    [ "${#expected}" -eq 64 ] \
        || die "[$node] missing or malformed $dir/stellereum.new.sha256 (re-run stage)"
    if ! actual="$(remote_sha "$node" "$dir/stellereum.new.next")"; then
        die "[$node] could not hash the staged binary"
    fi
    [ "$actual" = "$expected" ] \
        || die "[$node] staged sha256 $actual does not match expected $expected (re-run stage)"
    note "[$node] staged sha256 verified: $actual"

    start_h="$(node_height "$node" || true)"
    [ -n "$start_h" ] && note "[$node] height before restart: $start_h"

    # --- 2. T0, swap, restart ------------------------------------------------
    t0="$(now_ms)"
    note "[$node] T0: swapping binary and restarting $unit"
    # Pause the liveness guard so it cannot start a SECOND instance while the
    # unit is coming down (see guard_unit()).
    guard="$(guard_unit)"
    q_guard="$(printf '%q' "$guard")"
    nrun_long "$node" "$sysctl stop $q_guard >/dev/null 2>&1 || true"
    if ! nrun_long "$node" "cd $q_dir && cp -f stellereum stellereum.prev && mv -f stellereum.new.next stellereum && $sysctl restart $q_unit"; then
        nrun_long "$node" "$sysctl start $q_guard >/dev/null 2>&1 || true"
        if [ "$CANARY" -eq 1 ]; then
            warn "[$node] swap/restart failed; $dir/stellereum.prev holds the previous binary"
            return 1
        fi
        die "[$node] swap/restart failed; $dir/stellereum.prev holds the previous binary"
    fi
    nrun_long "$node" "$sysctl start $q_guard >/dev/null 2>&1 || true"

    deadline=$(( $(date +%s) + 120 ))
    t_active=""
    while :; do
        if nrun "$node" "$sysctl is-active --quiet $q_unit" 2>/dev/null; then
            active=1
            t_active="$(now_ms)"
            break
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            break
        fi
        sleep 1
    done
    if [ "$active" -ne 1 ]; then
        warn "[$node] $unit did not become active within 120 s"
        warn "[$node] inspect: ssh + journalctl (unit $unit); rollback: mv stellereum.prev stellereum + restart"
        return 1
    fi

    # --- 3. wait until the local RPC is within 5 blocks of the public tip ----
    deadline=$(( $(date +%s) + CATCHUP_SECS ))
    while :; do
        tip="$(public_tip "$node" || true)"
        local_h="$(node_height "$node" || true)"
        if [[ "$local_h" =~ ^[0-9]+$ ]]; then
            if [[ "$tip" =~ ^[0-9]+$ ]]; then
                if [ "$local_h" -ge $((tip - 5)) ]; then
                    caught=1
                    break
                fi
            elif [[ "$start_h" =~ ^[0-9]+$ ]] && [ "$local_h" -gt "$start_h" ]; then
                caught=1
                break
            fi
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            break
        fi
        waited=$((waited + 2))
        if [ "$waited" -ge 10 ]; then
            waited=0
            note "[$node] catching up: local=${local_h:-?} tip=${tip:-?} (budget ${CATCHUP_SECS}s)"
        fi
        sleep 2
    done

    t1="$(now_ms)"
    ms=$((t1 - t0))
    printf '\n'
    if [ -n "$t_active" ]; then
        note "[$node] restart downtime (T0 -> unit active): $(fmt_ms $((t_active - t0)))"
    fi
    note "[$node] unvoting window (T0 -> within 5 blocks of tip): $(fmt_ms "$ms")"
    if [ "$caught" -ne 1 ]; then
        warn "[$node] did not catch up within ${CATCHUP_SECS}s (local=${local_h:-?} tip=${tip:-?})"
        fail=1
    fi
    if [ "$ms" -gt "$DOWNTIME_WARN_MS" ]; then
        printf '\n'
        printf '%s\n' "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        printf '[rolling-deploy] JAIL RISK: the node was not voting for %s\n' "$(fmt_ms "$ms")"
        printf '[rolling-deploy] jail budget is %d misses x %d ms = %s; warn above %s\n' \
            "$JAIL_MISSES" "$BLOCK_MS" "$(jail_budget_text | sed 's/^.*= //')" \
            "$(fmt_s1 "$DOWNTIME_WARN_MS")"
        printf '%s\n' "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        printf '\n'
    fi

    # --- 4. validator jail state --------------------------------------------
    vid="${VALIDATOR:-$(node_validator "$node")}"
    if ! check_validator "$node" "$dir" "$vid"; then
        fail=1
    fi

    # --- 5. backoff: the cluster must still be 4/4 ---------------------------
    if ! cluster_check; then
        warn "ABORT: cluster health check failed after activating $node"
        return 1
    fi
    [ "$fail" -eq 0 ] || return 1
    note "[$node] activation complete"
}

rollback_canary_node() {
    local node="$1" dir unit sysctl guard q_dir q_unit q_guard q_prev
    dir="$(node_attr "$node" DIR)"
    unit="$(node_attr "$node" SERVICE)"
    sysctl="$(sysctl_for "$node")"
    guard="$(guard_unit)"
    q_dir="$(printf '%q' "$dir")"
    q_unit="$(printf '%q' "$unit")"
    q_guard="$(printf '%q' "$guard")"
    q_prev="$(printf '%q' "$dir/stellereum.prev")"

    warn "[$node] CANARY ROLLBACK: restoring $dir/stellereum.prev -> $dir/stellereum and restarting $unit"
    if ! nrun "$node" "test -f $q_prev"; then
        warn "[$node] cannot rollback: $dir/stellereum.prev is missing"
        return 1
    fi
    nrun_long "$node" "$sysctl stop $q_guard >/dev/null 2>&1 || true"
    if ! nrun_long "$node" "cd $q_dir && mv -f stellereum.prev stellereum && $sysctl restart $q_unit"; then
        nrun_long "$node" "$sysctl start $q_guard >/dev/null 2>&1 || true"
        warn "[$node] CANARY ROLLBACK FAILED during restore/restart"
        return 1
    fi
    nrun_long "$node" "$sysctl start $q_guard >/dev/null 2>&1 || true"
    note "[$node] canary rollback complete; $unit restarted on previous binary"
}

canary_soak() {
    local node="$1" dir vid start_h cur_h prev_h deadline now sleep_for
    dir="$(node_attr "$node" DIR)"
    vid="${VALIDATOR:-$(node_validator "$node")}"

    start_h="$(node_height "$node" || true)"
    case "$start_h" in
        ''|*[!0-9]*)
            warn "[$node] canary soak: local RPC height unavailable at soak start"
            return 1
            ;;
    esac
    prev_h="$start_h"
    note "[$node] canary soak: waiting ${CANARY_SOAK_SECS}s (initial local height=$start_h)"

    deadline=$(( $(date +%s) + CANARY_SOAK_SECS ))
    while :; do
        now="$(date +%s)"
        if [ "$now" -ge "$deadline" ]; then
            break
        fi
        sleep_for=$(( deadline - now ))
        if [ "$sleep_for" -gt 5 ]; then
            sleep_for=5
        fi
        sleep "$sleep_for"

        cur_h="$(node_height "$node" || true)"
        case "$cur_h" in
            ''|*[!0-9]*)
                warn "[$node] canary soak: local RPC height unreadable during soak"
                return 1
                ;;
        esac
        if [ "$cur_h" -lt "$prev_h" ]; then
            warn "[$node] canary soak: local RPC height regressed ($prev_h -> $cur_h)"
            return 1
        fi
        prev_h="$cur_h"
        if ! check_validator "$node" "$dir" "$vid"; then
            warn "[$node] canary soak: validator jailed during soak"
            return 1
        fi
        if ! cluster_check; then
            warn "[$node] canary soak: cluster health check failed during soak"
            return 1
        fi
    done

    cur_h="$(node_height "$node" || true)"
    case "$cur_h" in
        ''|*[!0-9]*)
            warn "[$node] canary soak: local RPC height unreadable at end of soak"
            return 1
            ;;
    esac
    if [ "$CANARY_SOAK_SECS" -gt 0 ] && [ "$cur_h" -le "$start_h" ]; then
        warn "[$node] canary soak: local RPC height did not advance over ${CANARY_SOAK_SECS}s ($start_h -> $cur_h)"
        return 1
    fi
    if ! check_validator "$node" "$dir" "$vid"; then
        return 1
    fi
    if ! cluster_check; then
        return 1
    fi
    note "[$node] canary soak PASSED: height $start_h -> $cur_h over ${CANARY_SOAK_SECS}s, not jailed, cluster healthy"
    return 0
}

do_activate() {
    local node json

    if [ "$DRY_RUN" -eq 1 ]; then
        show_plan
        return 0
    fi

    note "jail budget: $(jail_budget_text); warn above $(fmt_s1 "$DOWNTIME_WARN_MS")"
    note "public RPC: $PUBLIC_RPC"

    if ! json="$(fetch_cluster_json)"; then
        die "cannot read stell_getValidators before the rollout; refusing to start"
    fi
    BASELINE_COUNT="$(printf '%s' "$json" | jq -r '(.result.validators // .validators) | length')"
    [[ "$BASELINE_COUNT" =~ ^[0-9]+$ ]] || die "invalid baseline validator count from RPC: $BASELINE_COUNT"
    note "baseline cluster: ${BASELINE_COUNT}/${CLUSTER_SIZE} validators, fragile=$(printf '%s' "$json" | jq -r '(.result.fragile // .fragile // false)')"
    if [ "$BASELINE_COUNT" -lt 3 ]; then
        die "cluster already has ${BASELINE_COUNT} validators; fix that before a rolling restart"
    fi

    if [ "$CANARY" -eq 1 ]; then
        node="${NODES[0]}"
        note "=== CANARY activating node $node (soak ${CANARY_SOAK_SECS}s; remaining nodes will NOT be touched) ==="
        if ! activate_one "$node" || ! canary_soak "$node"; then
            warn "CANARY FAILED on node $node; rolling back and aborting rollout"
            rollback_canary_node "$node" || true
            warn "ROLLOUT ABORTED after canary failure on $node; remaining nodes untouched"
            exit 1
        fi
        note "CANARY SUCCEEDED on node $node; remaining nodes untouched (re-run without --canary to roll out the rest)"
        return 0
    fi

    for node in "${NODES[@]}"; do
        note "=== activating node $node ==="
        if ! activate_one "$node"; then
            warn "ROLLOUT ABORTED after node $node; nodes not yet touched keep running the old binary"
            exit 1
        fi
        note "=== node $node done ==="
    done
    note "rollout complete: ${#NODES[@]} node(s) on the staged binary"
}

while [ $# -gt 0 ]; do
    case "$1" in
        stage|activate) COMMAND="$1"; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --canary) CANARY=1; shift ;;
        --canary-soak-secs) [ $# -ge 2 ] || die "--canary-soak-secs needs a value"; CANARY_SOAK_SECS="$2"; shift 2 ;;
        --canary-soak-secs=*) CANARY_SOAK_SECS="${1#*=}"; shift ;;
        --nodes) [ $# -ge 2 ] || die "--nodes needs a value"; NODE_SPEC="$2"; shift 2 ;;
        --nodes=*) NODE_SPEC="${1#*=}"; shift ;;
        --public-rpc) [ $# -ge 2 ] || die "--public-rpc needs a value"; PUBLIC_RPC="$2"; shift 2 ;;
        --public-rpc=*) PUBLIC_RPC="${1#*=}"; shift ;;
        --validator) [ $# -ge 2 ] || die "--validator needs a value"; VALIDATOR="$2"; shift 2 ;;
        --validator=*) VALIDATOR="${1#*=}"; shift ;;
        --unjail-on-jail) UNJAIL_ON_JAIL=1; shift ;;
        --withdrawal-key-file) [ $# -ge 2 ] || die "--withdrawal-key-file needs a value"; WITHDRAWAL_KEY_FILE="$2"; shift 2 ;;
        --withdrawal-key-file=*) WITHDRAWAL_KEY_FILE="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; while [ $# -gt 0 ]; do POSITIONAL+=("$1"); shift; done ;;
        -*) die "unknown flag: $1" ;;
        *) POSITIONAL+=("$1"); shift ;;
    esac
done

[ -r "$CONF" ] || die "cluster conf not found: $CONF"
# shellcheck disable=SC1090
. "$CONF"

# The jail budget is `42 x tempo`, and the tempo comes from the fleet's
# expected config (or an explicit operator override). Recompute AFTER the
# conf is sourced so the reported budget matches the live 800 ms fleet.
BLOCK_MS="${STELL_MIN_BLOCK_MS:-${EXPECT_STELL_MIN_BLOCK_MS:-$BLOCK_MS}}"
[[ "$BLOCK_MS" =~ ^[0-9]+$ ]] || die "BLOCK_MS must be a non-negative integer: $BLOCK_MS"
DOWNTIME_WARN_MS=$((JAIL_MISSES * BLOCK_MS * 9 / 10))

command -v jq >/dev/null 2>&1 || die "jq is required (local parsing only; nodes need no jq)"

if [ -n "$VALIDATOR" ]; then
    [[ "$VALIDATOR" =~ ^[0-9a-fA-F]{64}$ ]] || die "--validator needs a 64-hex validator id"
fi

case "$CANARY_SOAK_SECS" in
    ''|*[!0-9]*) die "--canary-soak-secs must be a non-negative integer: $CANARY_SOAK_SECS" ;;
esac

if [ "$COMMAND" = "stage" ] && [ "$CANARY" -eq 1 ]; then
    die "--canary applies to activate (or --dry-run), not stage"
fi

if [ ${#POSITIONAL[@]} -gt 0 ]; then
    if [ "$COMMAND" = "stage" ] && [ -z "$BINARY" ]; then
        BINARY="${POSITIONAL[0]}"
        POSITIONAL=("${POSITIONAL[@]:1}")
    fi
    if [ ${#POSITIONAL[@]} -gt 0 ]; then
        extra="${POSITIONAL[*]}"
        NODE_SPEC="${NODE_SPEC:+$NODE_SPEC }$extra"
    fi
fi

if [ -z "$COMMAND" ]; then
    [ "$DRY_RUN" -eq 1 ] || { usage >&2; die "missing phase: stage <binary> | activate"; }
fi

read_nodes "$NODE_SPEC"

if [ -n "$VALIDATOR" ] && [ "${#NODES[@]}" -ne 1 ]; then
    die "--validator is for a single-node run; select one node with --nodes"
fi

case "$COMMAND" in
    stage) do_stage "$BINARY" ;;
    activate) do_activate ;;
    "") show_plan ;;
esac
