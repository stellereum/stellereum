#!/usr/bin/env bash
# ==============================================================================
# Stellereum Fast Sync & Cluster Management Tool (TON & Solana Architecture)
# Features:
#   1. Status Dashboard (N=4 Validators + Explorer Tip)
#   2. HTTP-based Fast Sync (zstd streaming from https://rpc.stellereum.org/snapshot/latest.tar.zst)
#   3. Push / Pull Local Point-in-time Snapshots
#   4. Atomic Parallel Binary Deploy
#   5. Auto-heal Watchdog (detects lagging nodes and heals them automatically)
#   6. `health`   — the operator health screen: validator set + power, shard
#      heads, the chain tip per shard, the indexer tip, the RPC round-trip
#      latency — EXTENDED with the per-node cluster table: service state,
#      inode usage, orphan chunk count, the pubsub topic, the consensus lock,
#      the binary path + hash and the service's last exit code.
#   7. `preflight` — FAIL-CLOSED pre-deploy check. A mixed-config cluster is
#      what killed the chain: this refuses to deploy and names every
#      difference.
#   8. `lockclear <node>` — clear a stale consensus lock safely.
#   9. `topic <node>`   — print the pubsub topic a node uses.
#  10. `doctor [node]`  — single-node local diagnosis (delegates to doctor.sh).
# ==============================================================================

set -eo pipefail

SNAPSHOT_HTTP_URL="https://rpc.stellereum.org/snapshot/latest.tar.zst"
SNAPSHOT_META_URL="https://rpc.stellereum.org/snapshot/meta.json"

# The ssh targets, the node dirs and the service names live in
# cluster-nodes.conf (sourced below) — ONE place, machine-readable, because
# the topology is exactly what drifted during the deployment attempt.
BIN_SRC="${BIN_SRC:-/home/imm/stellereum-project/stellereum/target/release/stellereum}"

# --- the cluster topology (node list, env files, units, expected values) ---
# Sourced FIRST so its values win over the defaults below.
STELL_CONF="${STELL_CONF:-/home/imm/stellereum-project/scripts/cluster-nodes.conf}"
if [ -r "$STELL_CONF" ]; then
    # shellcheck disable=SC1090
    . "$STELL_CONF"
fi

# The legacy names the older sub-commands use, mapped onto the conf.
NODE_B_LOCAL="${NODE_B_DIR}"
NODE_B_BIN="${NODE_B_DIR}/stellereum"

# --- health screen defaults (overridable with --rpc / --indexer) -----------
HEALTH_RPC="${STELL_RPC:-${HEALTH_RPC:-http://127.0.0.1:8546}}"
HEALTH_INDEXER="${STELL_INDEXER:-${HEALTH_INDEXER:-http://127.0.0.1:8081}}"
HEALTH_TIMEOUT="${STELL_HEALTH_TIMEOUT:-5}"
# The cluster part of `health` is remote; it needs its own timeout. The probe
# walks the chunk directory of every node, which on a node with 600k orphan
# chunks takes a while.
PROBE_TIMEOUT="${STELL_PROBE_TIMEOUT:-120}"

function log() {
    echo -e "\033[1;34m[stell-sync]\033[0m $*"
}

function err() {
    echo -e "\033[1;31m[ERROR]\033[0m $*" >&2
}

function success() {
    echo -e "\033[1;32m[OK]\033[0m $*"
}

function warn() {
    echo -e "\033[1;33m[WARN]\033[0m $*"
}

function get_height() {
    local endpoint="$1"
    local res
    res=$(curl -s -A "curl/8.0" --connect-timeout 2 -m 3 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":{}}' "$endpoint" 2>/dev/null || true)
    if [[ "$res" =~ \"result\":\"0x([0-9a-fA-F]+)\" ]]; then
        printf "%d" "0x${BASH_REMATCH[1]}"
    else
        echo "offline"
    fi
}

function show_status() {
    log "Checking Stellereum Cluster Status (N=4 Validators)..."
    echo "================================================================================"
    printf "%-10s %-25s %-16s %-12s\n" "NODE" "ENDPOINT" "HEIGHT (SHARD 0)" "STATUS"
    echo "================================================================================"

    # Node A
    local h_a
    h_a=$(get_height "https://rpc.stellereum.org")
    printf "%-10s %-25s %-16s %-12s\n" "Node A" "rpc.stellereum.org" "#$h_a" "$([[ "$h_a" != "offline" ]] && echo "ACTIVE" || echo "DOWN")"

    # Node B
    local h_b
    h_b=$(get_height "http://127.0.0.1:8546")
    printf "%-10s %-25s %-16s %-12s\n" "Node B" "127.0.0.1:8546 (local)" "#$h_b" "$([[ "$h_b" != "offline" ]] && echo "ACTIVE" || echo "DOWN")"

    # Node C
    local h_c
    h_c=$(ssh $NODE_C_SSH_OPTS $NODE_C_SSH "curl -s -m 2 http://127.0.0.1:8545 -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_blockNumber\",\"params\":{}}' | grep -o '\"result\":\"0x[0-9a-fA-F]*\"' | cut -d'\"' -f4" 2>/dev/null || true)
    if [[ "$h_c" =~ 0x([0-9a-fA-F]+) ]]; then
        h_c=$(printf "%d" "$h_c")
    else
        h_c="syncing"
    fi
    printf "%-10s %-25s %-16s %-12s\n" "Node C" "77.110.96.68 (Knanserver)" "#$h_c" "$([[ "$h_c" =~ ^[0-9]+$ ]] && echo "ACTIVE" || echo "LAGGING")"

    # Node D
    local h_d
    h_d=$(ssh $NODE_D_SSH_OPTS $NODE_D_SSH "curl -s -m 2 http://127.0.0.1:8545 -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_blockNumber\",\"params\":{}}' | grep -o '\"result\":\"0x[0-9a-fA-F]*\"' | cut -d'\"' -f4" 2>/dev/null || true)
    if [[ "$h_d" =~ 0x([0-9a-fA-F]+) ]]; then
        h_d=$(printf "%d" "$h_d")
    else
        h_d="syncing"
    fi
    printf "%-10s %-25s %-16s %-12s\n" "Node D" "138.124.102.200 (Capitalist)" "#$h_d" "$([[ "$h_d" =~ ^[0-9]+$ ]] && echo "ACTIVE" || echo "LAGGING")"

    echo "================================================================================"
    local exp_tip
    exp_tip=$(curl -s https://explorer.stellereum.org/api/v2/stats 2>/dev/null | grep -o '"tip_height":[0-9]*' | cut -d: -f2 || echo "n/a")
    echo "Explorer Tip: #${exp_tip}"

    local meta
    meta=$(curl -s --connect-timeout 2 -m 3 "$SNAPSHOT_META_URL" 2>/dev/null || true)
    if [[ "$meta" =~ \"height\":([0-9]+) ]]; then
        echo "HTTP Snapshot: #${BASH_REMATCH[1]} ($(echo "$meta" | grep -o '"size_bytes":[0-9]*' | cut -d: -f2 | awk '{printf "%.1f MB", $1/1024/1024}'))"
    fi
}

function http_sync_local() {
    log "Performing HTTP Fast-Sync for local Node B from $SNAPSHOT_HTTP_URL..."
    systemctl --user stop stell-nodeB.service || true
    rm -rf "$NODE_B_LOCAL/data/store" "$NODE_B_LOCAL/data/store-shard*"
    curl -sL "$SNAPSHOT_HTTP_URL" | tar -I 'zstd -d' -xf - -C "$NODE_B_LOCAL/data/"
    rm -f "$NODE_B_LOCAL/data/store"/snap* "$NODE_B_LOCAL/data/store-shard*"/snap* 2>/dev/null || true
    rm -f "$NODE_B_LOCAL/data/mempool.bin"
    systemctl --user start stell-nodeB.service
    success "Local Node B synced from HTTP snapshot and running!"
}

function http_sync_remote() {
    local node_name="$1"
    local ssh_dest="$2"
    local remote_dir="$3"
    local svc_name="$4"
    # The extra ssh options (e.g. a non-standard port) come from the caller.
    local SSH_OPTS="${5:-}"

    log "Performing HTTP Fast-Sync for $node_name..."
    ssh $SSH_OPTS $ssh_dest "systemctl stop $svc_name && rm -rf $remote_dir/data/store $remote_dir/data/store-shard* && curl -sL $SNAPSHOT_HTTP_URL | tar -I 'zstd -d' -xf - -C $remote_dir/data/ && rm -f $remote_dir/data/store*/snap* 2>/dev/null || true && chown -R root:root $remote_dir/data/store* && rm -f $remote_dir/data/mempool.bin && systemctl start $svc_name"
    success "$node_name synced from HTTP snapshot and running!"
}

function auto_heal() {
    log "Running Auto-Heal Watchdog across cluster..."
    local tip
    tip=$(get_height "https://rpc.stellereum.org")
    if [[ "$tip" == "offline" || "$tip" -eq 0 ]]; then
        err "Cannot reach Node A RPC to determine tip. Aborting auto-heal."
        return 1
    fi

    log "Current cluster tip: #$tip"

    # Check Node C
    local hc
    hc=$(ssh $NODE_C_SSH_OPTS $NODE_C_SSH "curl -s -m 2 http://127.0.0.1:8545 -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_blockNumber\",\"params\":{}}' | grep -o '\"result\":\"0x[0-9a-fA-F]*\"' | cut -d'\"' -f4" 2>/dev/null || true)
    if [[ "$hc" =~ 0x([0-9a-fA-F]+) ]]; then
        hc=$((16#${BASH_REMATCH[1]}))
    else
        hc=0
    fi

    if (( tip - hc > 100 || hc == 0 )); then
        warn "Node C is lagging (at #$hc vs tip #$tip, gap $((tip - hc))). Healing via HTTP snapshot..."
        http_sync_remote "Node C" "$NODE_C_SSH" "$NODE_C_DIR" "stell-nodeC.service" "$NODE_C_SSH_OPTS"
    else
        success "Node C is healthy (#$hc, gap $((tip - hc)))"
    fi

    # Check Node D
    local hd
    hd=$(ssh $NODE_D_SSH_OPTS $NODE_D_SSH "curl -s -m 2 http://127.0.0.1:8545 -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_blockNumber\",\"params\":{}}' | grep -o '\"result\":\"0x[0-9a-fA-F]*\"' | cut -d'\"' -f4" 2>/dev/null || true)
    if [[ "$hd" =~ 0x([0-9a-fA-F]+) ]]; then
        hd=$((16#${BASH_REMATCH[1]}))
    else
        hd=0
    fi

    if (( tip - hd > 100 || hd == 0 )); then
        warn "Node D is lagging (at #$hd vs tip #$tip, gap $((tip - hd))). Healing via HTTP snapshot..."
        http_sync_remote "Node D" "$NODE_D_SSH" "$NODE_D_DIR" "stell-nodeD.service"
    else
        success "Node D is healthy (#$hd, gap $((tip - hd)))"
    fi
}

function deploy_binaries() {
    log "Deploying newly compiled stellereum binary to all nodes..."
    if [[ ! -f "$BIN_SRC" ]]; then
        err "Binary $BIN_SRC not found. Compiling first..."
        cargo build --release --manifest-path /home/imm/stellereum-project/stellereum/Cargo.toml
    fi

    log "Uploading binary in parallel..."
    # A-path (R3 CODE-TAILS fix): node A runs /root/nodeA/stellereum
    # ($NODE_A_DIR/stellereum, the unit's ExecStart), NOT the cargo target
    # dir. The old hardcoded /root/stellereum/target/release/stellereum
    # deployed to a path nothing executes (and tripped the preflight's own
    # "binary runs from a cargo target dir" gate). C/D already used their
    # $NODE_*_DIR; A now does the same.
    scp "$BIN_SRC" $NODE_A_SSH:$NODE_A_DIR/stellereum.new &
    scp "$BIN_SRC" $NODE_D_SSH:$NODE_D_DIR/stellereum.new &
    scp $(node_scp_opts C) "$BIN_SRC" "$NODE_C_SSH:$NODE_C_DIR/stellereum.new" &
    # Node B runs its own copy OUTSIDE the cargo target dir: a concurrent
    # `cargo build`/`cargo clean` in the shared target directory removes
    # target/release/stellereum and takes the node down with it (observed
    # 2026-10-21: the whole target/release dir was deleted under a running
    # node, and the validator crash-looped on 203/EXEC).
    cp -f "$BIN_SRC" "$NODE_B_BIN.new" &
    wait

    log "Atomic binary swap and service restart..."
    ssh $NODE_A_SSH "systemctl stop stell-nodeA.service && mv -f $NODE_A_DIR/stellereum.new $NODE_A_DIR/stellereum && chmod +x $NODE_A_DIR/stellereum && systemctl start stell-nodeA.service" &
    ssh $NODE_D_SSH "systemctl stop stell-nodeD.service && mv -f $NODE_D_DIR/stellereum.new $NODE_D_DIR/stellereum && chmod +x $NODE_D_DIR/stellereum && systemctl start stell-nodeD.service" &
    ssh $NODE_C_SSH_OPTS $NODE_C_SSH "systemctl stop stell-nodeC.service && mv -f $NODE_C_DIR/stellereum.new $NODE_C_DIR/stellereum && chmod +x $NODE_C_DIR/stellereum && systemctl start stell-nodeC.service" &
    systemctl --user stop stell-nodeB.service && mv -f "$NODE_B_BIN.new" "$NODE_B_BIN" && chmod +x "$NODE_B_BIN" && systemctl --user start stell-nodeB.service &
    wait
    success "All nodes updated with new binary and running!"
}

# ==============================================================================
# `health` — the operator health screen.
#
# Prints the NEW health signals of the remediation wave:
#   * the validator set with every member's power, the total power and the
#     quorum (including the `fragile` flag: true when the quorum needs 100%
#     of the set, i.e. one halt stops the chain);
#   * the shard heads (per shard: type, tip height, tip hash, local or not);
#   * the chain tip PER SHARD;
#   * the indexer tip;
#   * the RPC round-trip latency;
#   * THE CLUSTER TABLE (new): every node's service state (DOWN /
#     CRASH-LOOPING are named as such), inode usage, orphan chunk count, the
#     pubsub topic it is on, its consensus lock, its binary path + hash and
#     the service's last exit code.
#
# Exit code 0 when every check passed, 1 when any of them did not, so it can
# be used as a cron / alert probe.
# ==============================================================================

# One JSON-RPC call. Prints the raw body on stdout, nothing on stderr.
function rpc_call() {
    local endpoint="$1" method="$2" params="${3:-{\}}"
    curl -s --connect-timeout "$HEALTH_TIMEOUT" -m "$HEALTH_TIMEOUT" \
         -H "Content-Type: application/json" \
         -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}" \
         "$endpoint" 2>/dev/null || true
}

# Extract a top-level scalar field from a JSON object without jq.
# Tolerant of whitespace around the colon (the node emits compact JSON, the
# indexer and a proxy may not).
function json_str() {
    local body="$1" key="$2"
    printf '%s' "$body" \
        | grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | head -1 \
        | sed 's/.*:[[:space:]]*"//; s/"$//' || true
}

function json_num() {
    local body="$1" key="$2"
    printf '%s' "$body" \
        | grep -o "\"${key}\"[[:space:]]*:[[:space:]]*[-0-9.]*" \
        | head -1 \
        | sed 's/.*:[[:space:]]*//' || true
}

function json_bool() {
    local body="$1" key="$2"
    if printf '%s' "$body" | grep -q "\"${key}\"[[:space:]]*:[[:space:]]*true"; then
        echo "true"
    elif printf '%s' "$body" | grep -q "\"${key}\"[[:space:]]*:[[:space:]]*false"; then
        echo "false"
    else
        echo "n/a"
    fi
}

# The raw (unquoted) value of a key that may be a string, a number or null.
function json_raw() {
    local body="$1" key="$2"
    printf '%s' "$body" \
        | grep -o "\"${key}\"[[:space:]]*:[[:space:]]*[^,}]*" \
        | head -1 \
        | sed 's/.*:[[:space:]]*//; s/[[:space:]]*$//' || true
}

# Split a JSON body into its innermost objects, one per line. The node's
# arrays of flat objects (validators, shards) have no nested braces, so this
# yields exactly one line per element.
function json_objects() {
    printf '%s' "$1" | grep -o '{[^{}]*}'
}

# A field of ONE flat object.
function obj_str() {
    local obj="$1" key="$2"
    printf '%s' "$obj" \
        | grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" \
        | head -1 \
        | sed 's/.*:[[:space:]]*"//; s/"$//' || true
}

function obj_num() {
    local obj="$1" key="$2"
    printf '%s' "$obj" \
        | grep -o "\"${key}\"[[:space:]]*:[[:space:]]*[-0-9]*" \
        | head -1 \
        | sed 's/.*:[[:space:]]*//' || true
}

function obj_bool() {
    local obj="$1" key="$2"
    if printf '%s' "$obj" | grep -q "\"${key}\"[[:space:]]*:[[:space:]]*true"; then
        echo "true"
    elif printf '%s' "$obj" | grep -q "\"${key}\"[[:space:]]*:[[:space:]]*false"; then
        echo "false"
    else
        echo "n/a"
    fi
}

# ==============================================================================
# The cluster probe: run lib/nodeprobe.sh on a node (locally or over ssh) and
# return its `key=value` output.
# ==============================================================================
PROBE_DIRTY=0

# The ssh options of a node, translated for scp (which spells the port
# option -P, not -p — `scp -p 2222 file host:` tries to copy a local file
# named "2222").
function node_scp_opts() {
    local n="$1" o
    o="$(node_conf "$n" SSH_OPTS)"
    printf '%s' "$o" | sed 's/-p \([0-9][0-9]*\)/-P \1/g'
}

# Read a per-node field out of the cluster conf (NODE_<N>_<field>).
function node_conf() {
    local n="$1" f="$2" v
    eval "v=\${NODE_${n}_${f}:-}"
    printf '%s' "$v"
}

# The probe is cached per node for the lifetime of the command: it is one ssh
# round trip (and a walk of the node's chunk directory), and the health screen
# asks for the same node's state more than once.
declare -A PROBE_CACHE=()

# probe_node <node> — echoes the probe output, or nothing on failure.
function probe_node() {
    local n="$1"
    if [[ -n "${PROBE_CACHE[$n]:-}" ]]; then
        printf '%s' "${PROBE_CACHE[$n]}"
        return 0
    fi
    local ssh_target opts dir env_file service scope rpc shard_id orphans
    ssh_target="$(node_conf "$n" SSH)"
    opts="$(node_conf "$n" SSH_OPTS)"
    dir="$(node_conf "$n" DIR)"
    env_file="$(node_conf "$n" ENV)"
    service="$(node_conf "$n" SERVICE)"
    scope="$(node_conf "$n" SCOPE)"
    rpc="$(node_conf "$n" RPC)"
    shard_id="$(node_conf "$n" SHARD_ID)"

    if [ -z "$NODPROBE" ] || [ ! -r "$NODPROBE" ]; then
        err "probe script not found: $NODPROBE"
        return 1
    fi

    local env_prefix
    env_prefix="STELL_PROBE_NODE=$n STELL_PROBE_DIR=$dir STELL_PROBE_ENV_FILE=$env_file"
    env_prefix="$env_prefix STELL_PROBE_SERVICE=$service STELL_PROBE_SERVICE_SCOPE=$scope"
    env_prefix="$env_prefix STELL_PROBE_RPC=$rpc STELL_PROBE_SHARD_ID=$shard_id"
    env_prefix="$env_prefix STELL_PROBE_ORPHANS=$HEALTH_ORPHANS"

    local out
    if [ -z "$ssh_target" ]; then
        # local node
        out="$(env $env_prefix sh "$NODPROBE" 2>/dev/null || true)"
    else
        # remote node. `sh -s` reads the probe from stdin; the parameters ride
        # in as environment assignments so nothing needs quoting twice.
        # shellcheck disable=SC2086
        out="$(timeout "$PROBE_TIMEOUT" ssh -o BatchMode=yes -o ConnectTimeout=8 $opts "$ssh_target" \
            "$env_prefix sh -s" < "$NODPROBE" 2>/dev/null || true)"
    fi
    PROBE_CACHE[$n]="$out"
    printf '%s' "$out"
}

# probe_field <node> <field> — one value out of the probe output.
function probe_field() {
    local n="$1" f="$2"
    local out
    out="$(probe_node "$n")"
    printf '%s' "$out" | sed -n "s/^${f}=//p" | head -1
}

# The service state of a node, NORMALISED to the words the operator needs:
# ACTIVE / DOWN / CRASH-LOOPING / FAILED / UNKNOWN.
function node_state() {
    local n="$1"
    local out st restarts exitcode
    out="$(probe_node "$n")"
    st="$(printf '%s' "$out" | sed -n 's/^service_state=//p' | head -1)"
    restarts="$(printf '%s' "$out" | sed -n 's/^service_restarts=//p' | head -1)"
    exitcode="$(printf '%s' "$out" | sed -n 's/^service_exit_code=//p' | head -1)"
    case "$st" in
        active)
            # 203 = EXEC (the binary is gone or not executable — the
            # `cargo clean` under a live node signature).
            if [ "$exitcode" = "203" ]; then
                echo "CRASH-LOOPING(203/EXEC)"
            elif [ -n "$restarts" ] && [ "$restarts" -ge 3 ] 2>/dev/null; then
                echo "CRASH-LOOPING(restarts=$restarts)"
            else
                echo "ACTIVE"
            fi
            ;;
        inactive|failed|deactivating) echo "DOWN" ;;
        activating)                   echo "STARTING" ;;
        "")                           echo "UNKNOWN" ;;
        *)                            echo "$st" ;;
    esac
}

# The cluster table for `health`.
function show_cluster_table() {
    local n st tip topic inodes orph lockh lockr binsha exitcode
    echo ""
    echo "-- CLUSTER TABLE ----------------------------------------------------"
    printf "  %-6s %-18s %-11s %-7s %-9s %-16s %-8s %-6s %s\n" \
        "NODE" "STATE" "TIP" "INODES" "ORPHANS" "TOPIC" "LOCK" "EXIT" "BIN-SHA256"
    echo "  --------------------------------------------------------------------------"
    for n in $STELL_NODES; do
        local out
        out="$(probe_node "$n")"
        if [ -z "$out" ]; then
            printf "  %-6s %-18s %-11s %-7s %-9s %-16s %-8s %s\n" \
                "$n" "UNREACHABLE" "-" "-" "-" "-" "-" "-"
            continue
        fi
        st="$(printf '%s' "$out" | sed -n 's/^service_state=//p' | head -1)"
        tip="$(printf '%s' "$out" | sed -n 's/^tip=//p' | head -1)"
        topic="$(printf '%s' "$out" | sed -n 's/^topic=//p' | head -1)"
        inodes="$(printf '%s' "$out" | sed -n 's/^inode_pct=//p' | head -1)"
        orph="$(printf '%s' "$out" | sed -n 's/^chunk_orphans=//p' | head -1)"
        lockh="$(printf '%s' "$out" | sed -n 's/^lock_height=//p' | head -1)"
        lockr="$(printf '%s' "$out" | sed -n 's/^lock_round=//p' | head -1)"
        locksrc="$(printf '%s' "$out" | sed -n 's/^lock_source=//p' | head -1)"
        # The persisted lock is readable only while the node is STOPPED (sled
        # locks the store), so a running node shows where the lock would come
        # from instead of a fake "none".
        if [ "$locksrc" != "store" ] && [ "$lockh" = "?" ]; then
            case "$locksrc" in
                "unavailable(store locked"*) lockh="n/a(node up)" ;;
                "unavailable(no ops tool"*) lockh="n/a(tool)" ;;
                "no-store")               lockh="n/a(no store)" ;;
                "none")                   lockh="none" ;;
                *)                        lockh="n/a" ;;
            esac
            lockr="-"
        fi
        binsha="$(printf '%s' "$out" | sed -n 's/^binary_sha256=//p' | head -1)"
        exitcode="$(printf '%s' "$out" | sed -n 's/^service_exit_code=//p' | head -1)"
        # normalise the state word
        case "$st" in
            active)
                if [ "$exitcode" = "203" ]; then st="CRASH-LOOPING(203)"
                elif [ -n "$(printf '%s' "$out" | sed -n 's/^service_restarts=//p' | head -1)" ] \
                     && [ "$(printf '%s' "$out" | sed -n 's/^service_restarts=//p' | head -1)" -ge 3 ] 2>/dev/null; then
                    st="CRASH-LOOPING"
                else
                    st="ACTIVE"
                fi
                ;;
            inactive|failed) st="DOWN" ;;
            activating)       st="STARTING" ;;
        esac
        [ -z "$st" ] && st="UNKNOWN"
        [ "${binsha:0:8}" = "?" ] && binsha="?"
        printf "  %-6s %-18s %-11s %-7s %-9s %-16s %-8s %-6s %s\n" \
            "$n" "$st" "$tip" "$inodes%" "$orph" "${topic:0:16}" "$lockh/$lockr" "$exitcode" "${binsha:0:12}"
    done
    echo ""
    echo "  (ORPHANS = chunk files under <data>/chunks that no live manifest in"
    echo "   kv.json references; LOCK = height/round of the persisted consensus"
    echo "   lock (readable only while the node is stopped: sled locks the store);"
    echo "   EXIT = the service's last exit code (203 = the binary is gone);"
    echo "   TIP = the masterchain height the node reports.)"
}

function show_health() {
    local rpc="$HEALTH_RPC" indexer="$HEALTH_INDEXER"
    local failures=0

    echo "================================================================================"
    echo " STELLEREUM HEALTH  ($(date -u '+%Y-%m-%dT%H:%M:%SZ'))"
    echo "   node RPC : $rpc"
    echo "   indexer  : $indexer"
    echo "================================================================================"

    # ---- 1. validator set + power -----------------------------------------
    echo ""
    echo "-- VALIDATOR SET --------------------------------------------------"
    local vs
    vs=$(rpc_call "$rpc" stell_getValidators)
    if [[ -z "$vs" ]] || ! printf '%s' "$vs" | grep -q '"validators"'; then
        warn "could not read the validator set from $rpc"
        failures=$((failures + 1))
    else
        local total_power quorum fragile fragile_reason
        total_power=$(json_str "$vs" "total_power")
        quorum=$(json_str "$vs" "quorum")
        fragile=$(json_bool "$vs" "fragile")
        fragile_reason=$(json_raw "$vs" "fragile_reason")
        # `fragile_reason` is `null` when the set is healthy; only show it when
        # it actually names something.
        [[ "$fragile_reason" == "null" || -z "$fragile_reason" ]] && fragile_reason=""

        printf "  %-4s %-66s %s\n" "RANK" "VALIDATOR" "POWER"
        printf "  %-4s %-66s %s\n" "----" "----------------------------------------------------------------" "-----"
        # The validator list is an array of {"validator":"<hex>","power":"<n>"}.
        local n=0
        while read -r vobj; do
            [[ -z "$vobj" ]] && continue
            local vaddr vpower
            vaddr=$(obj_str "$vobj" "validator")
            vpower=$(obj_str "$vobj" "power")
            [[ -z "$vaddr" ]] && continue
            n=$((n + 1))
            printf "  #%-3s %-66s %s\n" "$n" "$vaddr" "$vpower"
        done < <(json_objects "$vs")

        echo ""
        echo "  validators    : $n"
        echo "  total power   : ${total_power:-n/a}"
        echo "  quorum power  : ${quorum:-n/a}"
        echo "  fragile       : ${fragile:-n/a} ${fragile_reason:-}"
        if [[ "$fragile" == "true" ]]; then
            warn "the quorum needs 100% of the set: ONE validator down stops the chain"
            failures=$((failures + 1))
        fi
        if [[ -z "$total_power" || "$total_power" == "0" ]]; then
            err "the validator set has no power: the chain CANNOT finalise"
            failures=$((failures + 1))
        fi
    fi

    # ---- 2. shard heads + 3. the chain tip per shard ----------------------
    echo ""
    echo "-- SHARD HEADS / CHAIN TIP PER SHARD --------------------------------"
    local shards
    shards=$(rpc_call "$rpc" stell_getShards)
    if [[ -z "$shards" ]] || ! printf '%s' "$shards" | grep -q '"shards"'; then
        warn "could not read the shard topology from $rpc"
        failures=$((failures + 1))
    else
        printf "  %-6s %-12s %-12s %-18s %-7s %s\n" \
            "SHARD" "TYPE" "TIP HEIGHT" "TIP HASH" "LOCAL" "STATE ROOT"
        local master_tip="" total_shards
        total_shards=$(json_num "$shards" "total_shards")
        while read -r sobj; do
            [[ -z "$sobj" ]] && continue
            local sid stype sheight shash slocal sroot
            sid=$(obj_num "$sobj" "shard_id")
            stype=$(obj_str "$sobj" "type")
            sheight=$(obj_num "$sobj" "tip_height")
            shash=$(obj_str "$sobj" "tip_hash")
            sroot=$(obj_str "$sobj" "state_root")
            slocal=$(obj_bool "$sobj" "local")
            [[ -z "$sid" ]] && continue
            printf "  %-6s %-12s %-12s %-18s %-7s %s\n" \
                "$sid" "$stype" "$sheight" "${shash:0:16}" "$slocal" "${sroot:0:16}"
            if [[ "$stype" == "masterchain" ]]; then
                master_tip="$sheight"
            fi
        done < <(json_objects "$shards")
        echo ""
        echo "  total shards  : ${total_shards:-n/a}"
        echo "  masterchain tip: ${master_tip:-n/a}"
    fi

    # ---- the node's own tip (the masterchain height) ----------------------
    echo ""
    echo "-- NODE TIP ---------------------------------------------------------"
    local bn
    bn=$(rpc_call "$rpc" stell_blockNumber)
    local node_tip
    node_tip=$(printf '%s' "$bn" \
        | grep -o '"result"[[:space:]]*:[[:space:]]*"0x[0-9a-fA-F]*"' \
        | head -1 \
        | sed 's/.*"0x//; s/"$//' || true)
    if [[ -n "$node_tip" ]]; then
        echo "  stell_blockNumber : $((16#$node_tip))  (0x$node_tip)"
    else
        warn "could not read stell_blockNumber from $rpc"
        failures=$((failures + 1))
    fi

    # ---- 4. the indexer tip -----------------------------------------------
    echo ""
    echo "-- INDEXER TIP ------------------------------------------------------"
    local istatus itip
    istatus=$(curl -s --connect-timeout "$HEALTH_TIMEOUT" -m "$HEALTH_TIMEOUT" \
        "$indexer/api/v2/status" 2>/dev/null || true)
    itip=$(json_num "$istatus" "tip_height")
    if [[ -z "$itip" ]]; then
        # Fall back to the stats endpoint, which carries the same field.
        istatus=$(curl -s --connect-timeout "$HEALTH_TIMEOUT" -m "$HEALTH_TIMEOUT" \
            "$indexer/api/v2/stats" 2>/dev/null || true)
        itip=$(json_num "$istatus" "tip_height")
    fi
    if [[ -n "$itip" ]]; then
        echo "  indexer tip_height : $itip"
        if [[ -n "$node_tip" ]]; then
            local node_dec=$((16#$node_tip))
            local gap=$((node_dec - itip))
            echo "  lag vs node tip    : $gap block(s)"
            if (( gap > 100 )); then
                warn "the indexer is more than 100 blocks behind the node"
                failures=$((failures + 1))
            fi
        fi
    else
        warn "could not read the indexer tip from $indexer"
        failures=$((failures + 1))
    fi

    # ---- 5. the RPC round-trip latency ------------------------------------
    echo ""
    echo "-- RPC ROUND-TRIP LATENCY -------------------------------------------"
    local samples=5 i t0 t1 total_ms=0 best=""
    for (( i = 0; i < samples; i++ )); do
        t0=$(date +%s%N)
        rpc_call "$rpc" stell_blockNumber >/dev/null
        t1=$(date +%s%N)
        local ms=$(( (t1 - t0) / 1000000 ))
        total_ms=$(( total_ms + ms ))
        [[ -z "$best" ]] && best="$ms"
        (( ms < best )) && best="$ms"
    done
    local avg=$(( total_ms / samples ))
    echo "  samples            : $samples"
    echo "  average            : ${avg} ms"
    echo "  best               : ${best} ms"
    if (( avg > 1000 )); then
        warn "the RPC round-trip is above 1s: the node is busy or the link is slow"
        failures=$((failures + 1))
    fi

    # ---- 6. THE CLUSTER TABLE (new) ---------------------------------------
    show_cluster_table

    # ---- 7. the cluster's own problems ------------------------------------
    echo ""
    echo "-- CLUSTER PROBLEMS -------------------------------------------------"
    local n out state topic expect_topic shards ipct orph
    local problems=0
    for n in $STELL_NODES; do
        out="$(probe_node "$n")"
        if [[ -z "$out" ]]; then
            err "node $n is UNREACHABLE (no answer from the probe)"
            problems=$((problems + 1))
            continue
        fi
        state="$(printf '%s' "$out" | sed -n 's/^service_state=//p' | head -1)"
        expect_topic="$(printf '%s' "$out" | sed -n 's/^expected_topic=//p' | head -1)"
        topic="$(printf '%s' "$out" | sed -n 's/^topic=//p' | head -1)"
        shards="$(printf '%s' "$out" | sed -n 's/^env_STELL_SHARDS=//p' | head -1)"
        ipct="$(printf '%s' "$out" | sed -n 's/^inode_pct=//p' | head -1)"
        orph="$(printf '%s' "$out" | sed -n 's/^chunk_orphans=//p' | head -1)"
        case "$state" in
            active) ;;
            inactive|failed)
                err "node $n is DOWN (service state: $state)"
                problems=$((problems + 1)) ;;
            *)
                warn "node $n is in state '$state'" ;;
        esac
        if [[ "$topic" != "?" && "$expect_topic" != "?" && "$topic" != "$expect_topic" ]]; then
            err "node $n is on topic '$topic' but should be on '$expect_topic'"
            problems=$((problems + 1))
        fi
        if [[ -n "$ipct" && "$ipct" != "?" && "$ipct" -ge "$INODE_HARD_PCT" ]] 2>/dev/null; then
            err "node $n inode usage is ${ipct}% (>= ${INODE_HARD_PCT}%): the filesystem is about to go read-only"
            problems=$((problems + 1))
        elif [[ -n "$ipct" && "$ipct" != "?" && "$ipct" -ge "$INODE_WARN_PCT" ]] 2>/dev/null; then
            warn "node $n inode usage is ${ipct}% (>= ${INODE_WARN_PCT}%)"
        fi
        if [[ -n "$orph" && "$orph" != "?" && "$orph" != "skipped" && "$orph" -ge "$ORPHAN_WARN_COUNT" ]] 2>/dev/null; then
            warn "node $n holds $orph orphan chunk files (>= ${ORPHAN_WARN_COUNT}): run scripts/node-prune-cron.sh on it"
        fi
    done
    if (( problems == 0 )); then
        echo "  no cluster ERRORS (any warnings are listed above)"
    else
        failures=$((failures + problems))
    fi

    echo ""
    echo "================================================================================"
    if (( failures == 0 )); then
        success "all health checks passed"
        return 0
    fi
    err "$failures health check(s) failed"
    return 1
}

# ==============================================================================
# `preflight` — the fail-closed pre-deploy gate.
#
# A MIXED-CONFIG CLUSTER IS WHAT KILLED THE CHAIN. During the deployment
# attempt one node's `STELL_SHARDS` had regressed to `0` while the others had
# `0,1`; because the pubsub topic is derived from `registry.is_sharded()`, that
# node sat on a DIFFERENT TOPIC and never exchanged a single masterchain
# message — a validator silently isolated from the network, with ZERO log
# evidence. This check refuses to let that happen again:
#
#   * all nodes reachable (ssh + RPC)
#   * all on the SAME pubsub topic (and the topic the node is really on
#     matches the topic it SHOULD be on)
#   * the SAME STELL_SHARDS
#   * the same chain id
#   * the same genesis root (= the same chain epoch)
#   * the same STELL_ROUND_TIMEOUT_MS / STELL_DOWN_PROPOSER_TIMEOUT_MS /
#     STELL_MIN_BLOCK_MS / STELL_KEEP_BLOCKS / admission base-fee floor
#   * inode usage below the threshold on every node
#   * the binary path OUTSIDE the shared cargo target dir
#   * every node's service enabled
#
# Every difference is NAMED. Exit code 1 = refuse to deploy.
# ==============================================================================
function show_preflight() {
    local differences=0
    local n out

    echo "================================================================================"
    echo " STELLEREUM PREFLIGHT  ($(date -u '+%Y-%m-%dT%H:%M:%SZ'))"
    echo "   fail-closed: ANY difference below refuses the deploy"
    echo "================================================================================"

    # --- collect every node's state once -----------------------------------
    local -A PROBE
    for n in $STELL_NODES; do
        out="$(probe_node "$n")"
        if [[ -z "$out" ]]; then
            err "node $n is UNREACHABLE — the preflight cannot see it, so it cannot vouch for it"
            differences=$((differences + 1))
            continue
        fi
        PROBE[$n]="$out"
    done

    # --- 1. the config table ------------------------------------------------
    echo ""
    echo "-- CONFIG COMPARISON ------------------------------------------------"
    printf "  %-6s %-10s %-9s %-9s %-8s %-8s %-9s %-9s %-7s %-7s %-6s %s\n" \
        "NODE" "SHARDS" "ROUND_TO" "DOWN_PROP" "MIN_BLOCK" "KEEP" "CHAIN_ID" "BASE_FEE" "INODE%" "ORPHANS" "ENABLE" "TOPIC"
    echo "  ---------------------------------------------------------------------------------------------------"
    for n in $STELL_NODES; do
        [[ -z "${PROBE[$n]:-}" ]] && continue
        local p="${PROBE[$n]}"
        local f
        f() { printf '%s' "$p" | sed -n "s/^$1=//p" | head -1; }
        printf "  %-6s %-10s %-9s %-9s %-8s %-8s %-9s %-9s %-7s %-7s %-6s %s\n" \
            "$n" \
            "$(f env_STELL_SHARDS)" \
            "$(f env_STELL_ROUND_TIMEOUT_MS)" \
            "$(f env_STELL_DOWN_PROPOSER_TIMEOUT_MS)" \
            "$(f env_STELL_MIN_BLOCK_MS)" \
            "$(f env_STELL_KEEP_BLOCKS)" \
            "$(f chain_id)" \
            "$(f base_fee)" \
            "$(f inode_pct)" \
            "$(f chunk_orphans)" \
            "$(f service_enabled)" \
            "$(f topic)"
    done

    # --- 2. the differences, named -----------------------------------------
    echo ""
    echo "-- DIFFERENCES -----------------------------------------------------"
    local ref="" refn=""
    for n in $STELL_NODES; do
        [[ -z "${PROBE[$n]:-}" ]] && continue
        local p="${PROBE[$n]}"
        local f
        f() { printf '%s' "$p" | sed -n "s/^$1=//p" | head -1; }

        # (a) the shard set — a NETWORK-MEMBERSHIP parameter
        local shards; shards="$(f env_STELL_SHARDS)"
        if [[ "$shards" != "$EXPECT_STELL_SHARDS" ]]; then
            err "node $n: STELL_SHARDS=$shards, expected $EXPECT_STELL_SHARDS"
            err "        (a different shard set means a DIFFERENT PUBSUB TOPIC: the node is isolated from the network)"
            differences=$((differences + 1))
        fi

        # (b) the pubsub topic
        local topic expect_topic epoch
        topic="$(f topic)"; expect_topic="$(f expected_topic)"; epoch="$(f epoch)"
        if [[ "$topic" == "?" || -z "$topic" ]]; then
            err "node $n: the pubsub topic could not be read from the node's log"
            differences=$((differences + 1))
        elif [[ "$expect_topic" != "?" && "$topic" != "$expect_topic" ]]; then
            err "node $n: pubsub topic is '$topic', expected '$expect_topic'"
            differences=$((differences + 1))
        fi

        # (c) the consensus timeouts / retention
        local key val expected
        for key in STELL_ROUND_TIMEOUT_MS STELL_DOWN_PROPOSER_TIMEOUT_MS STELL_MIN_BLOCK_MS STELL_KEEP_BLOCKS; do
            val="$(f "env_$key")"
            expected="$(eval echo "\$EXPECT_$key")"
            if [[ "$val" != "$expected" ]]; then
                err "node $n: $key=$val, expected $expected"
                differences=$((differences + 1))
            fi
        done

        # (d) the chain id
        local cid; cid="$(f chain_id)"
        if [[ -n "$cid" && "$cid" != "?" && "$cid" != "$EXPECT_STELL_CHAIN_ID" ]]; then
            err "node $n: chain id $cid, expected $EXPECT_STELL_CHAIN_ID"
            differences=$((differences + 1))
        fi
        if [[ -z "$cid" || "$cid" == "?" ]]; then
            err "node $n: the chain id could not be read from its RPC"
            differences=$((differences + 1))
        fi

        # (e) the base-fee floor
        local bf; bf="$(f base_fee)"
        if [[ -n "$bf" && "$bf" != "?" && "$bf" != "$EXPECT_BASE_FEE" ]]; then
            err "node $n: admission base fee $bf, expected $EXPECT_BASE_FEE"
            differences=$((differences + 1))
        fi

        # (f) the genesis root / chain epoch
        if [[ -z "$ref" ]]; then
            ref="$epoch"; refn="$n"
        elif [[ "$epoch" != "?" && "$ref" != "?" && "$epoch" != "$ref" ]]; then
            err "node $n: chain epoch $epoch != node $refn's $ref (different genesis root => different chain)"
            differences=$((differences + 1))
        fi

        # (g) the inodes
        local ipct; ipct="$(f inode_pct)"
        if [[ -z "$ipct" || "$ipct" == "?" ]]; then
            err "node $n: inode usage could not be read"
            differences=$((differences + 1))
        elif [[ "$ipct" -ge "$INODE_HARD_PCT" ]] 2>/dev/null; then
            err "node $n: inode usage ${ipct}% >= ${INODE_HARD_PCT}% — the node will go read-only and drop out of consensus"
            differences=$((differences + 1))
        fi

        # (h) the binary must live OUTSIDE the shared cargo target dir
        local intarget binpath; intarget="$(f binary_in_target_dir)"; binpath="$(f binary_path)"
        if [[ "$intarget" == "yes" ]]; then
            err "node $n: the binary runs from a cargo target dir ($binpath) — a 'cargo clean' deletes it under the live node (203/EXEC crash-loop)"
            differences=$((differences + 1))
        fi

        # (i) the service must be enabled
        local en; en="$(f service_enabled)"
        if [[ "$en" != "enabled" ]]; then
            err "node $n: the service is '$en', not 'enabled'"
            differences=$((differences + 1))
        fi

        # (j) the service must be up
        local st; st="$(f service_state)"
        if [[ "$st" != "active" ]]; then
            err "node $n: the service is '$st', not 'active'"
            differences=$((differences + 1))
        fi

        # (k) the RPC must answer
        local rpcok; rpcok="$(f rpc)"
        if [[ "$rpcok" != "yes" ]]; then
            err "node $n: the RPC does not answer"
            differences=$((differences + 1))
        fi
    done

    # --- 3. the orphan chunk warning ---------------------------------------
    for n in $STELL_NODES; do
        [[ -z "${PROBE[$n]:-}" ]] && continue
        local orph; orph="$(printf '%s' "${PROBE[$n]}" | sed -n 's/^chunk_orphans=//p' | head -1)"
        if [[ -n "$orph" && "$orph" != "?" && "$orph" != "skipped" && "$orph" -ge "$ORPHAN_WARN_COUNT" ]] 2>/dev/null; then
            warn "node $n holds $orph orphan chunk files — run scripts/node-prune-cron.sh on it before/while it runs"
        fi
    done

    echo ""
    echo "================================================================================"
    if (( differences == 0 )); then
        success "PREFLIGHT PASSED — every node agrees; the deploy may proceed"
        return 0
    fi
    err "PREFLIGHT FAILED — $differences difference(s). REFUSING TO DEPLOY."
    echo "  Fix every line above, then re-run: $0 preflight"
    return 1
}

# ==============================================================================
# `topic <node>` — print the pubsub topic a node uses.
#
# The topic is derived the way the NODE derives it:
#   epoch  = hex(genesis_state_root[0..8])
#   sharded = STELL_SHARDS lists more than one shard
#   topic  = stellereum/consensus/v1/<epoch>              (single shard)
#            stellereum/consensus/v1/<epoch>/shard/<id>    (multi shard)
# The topic the node REALLY subscribed to is read back from its own log, so
# the two can be compared (a mismatch = the node is isolated).
# ==============================================================================
function show_topic() {
    local n="${1:-}"
    if [[ -z "$n" ]]; then
        err "usage: $0 topic <node>"
        return 2
    fi
    if ! is_known_node "$n"; then
        err "unknown node '$n' (known: $STELL_NODES)"
        return 2
    fi
    local out
    out="$(probe_node "$n")"
    if [[ -z "$out" ]]; then
        err "node $n is unreachable"
        return 1
    fi
    local f
    f() { printf '%s' "$out" | sed -n "s/^$1=//p" | head -1; }
    echo "node            : $n"
    echo "epoch           : $(f epoch)"
    echo "STELL_SHARDS    : $(f env_STELL_SHARDS)"
    echo "is_sharded      : $(f is_sharded)"
    echo "expected topic  : $(f expected_topic)"
    echo "subscribed topic: $(f topic)"
    echo "all topics      : $(f topics)"
    local t e
    t="$(f topic)"; e="$(f expected_topic)"
    if [[ "$t" != "?" && "$e" != "?" && "$t" != "$e" ]]; then
        err "MISMATCH: the node is on '$t' but should be on '$e' — it is isolated from the network"
        return 1
    fi
    return 0
}

function is_known_node() {
    local want="$1" n
    for n in $STELL_NODES; do
        [[ "$n" == "$want" ]] && return 0
    done
    return 1
}

# ==============================================================================
# `lockclear <node>` — clear a stale consensus lock, safely.
#
# WHAT A STALE LOCK IS: the node persists its consensus safety state (height,
# round, locked block hash) in the store under the meta key `consensus`. On
# restart the node restores it — and with the rule "never adopt a peer's
# round" a node that resumes at round 56 while its peers are at round 0 can
# NEVER rejoin. It has to be cleared by hand.
#
# WHAT THIS DOES, IN ORDER:
#   1. reads the node's checkpoint (needs the node STOPPED: sled holds an
#      exclusive lock on the store while the node runs);
#   2. compares the locked height/round with the peers' tip — refuses if the
#      node is NOT actually stuck behind its peers;
#   3. stops the service, clears the lock, starts the service again;
#   4. verifies the node comes back.
#
# It never touches the finalized pointer, so the node keeps its finalized
# head and only loses the stuck lock.
# ==============================================================================
function do_lockclear() {
    local n="${1:-}"
    local force="${2:-}"
    if [[ -z "$n" ]]; then
        err "usage: $0 lockclear <node> [--force]"
        return 2
    fi
    if ! is_known_node "$n"; then
        err "unknown node '$n' (known: $STELL_NODES)"
        return 2
    fi

    local dir svc scope ssh_target opts
    dir="$(node_conf "$n" DIR)"
    svc="$(node_conf "$n" SERVICE)"
    scope="$(node_conf "$n" SCOPE)"
    ssh_target="$(node_conf "$n" SSH)"
    opts="$(node_conf "$n" SSH_OPTS)"

    # The masterchain store is <node dir>/data/store.
    local store="$dir/data/store"
    local tool="$STELOPS_BIN"

    echo "== node $n =="
    echo "  node dir : $dir"
    echo "  service  : $svc"

    # --- 1. the peer tip (to prove the node is really behind) --------------
    local peer_tip=0 m
    for m in $STELL_NODES; do
        [[ "$m" == "$n" ]] && continue
        local t
        t="$(probe_field "$m" tip)"
        if [[ -n "$t" && "$t" != "?" ]]; then
            if (( t > peer_tip )); then peer_tip="$t"; fi
        fi
    done
    echo "  peer tip : $peer_tip"

    # --- 2. the checkpoint -------------------------------------------------
    # The store is locked while the node runs, so the checkpoint can only be
    # read with the node STOPPED. We stop it first (that is the only way).
    local sysctl_cmd="systemctl"
    [[ "$scope" == "user" ]] && sysctl_cmd="systemctl --user"

    local remote_run
    remote_run() {
        if [[ -z "$ssh_target" ]]; then
            # A local node: the command is a STRING, so it needs a shell.
            sh -c "$*" 2>&1
        else
            # ssh runs the command through the remote shell.
            # shellcheck disable=SC2086
            timeout 120 ssh -o BatchMode=yes -o ConnectTimeout=8 $opts "$ssh_target" "$*" 2>&1
        fi
    }

    # The tool must be ON the node: a local node uses the local build, a
    # remote node gets a copy staged at $STELOPS_REMOTE.
    if [[ -n "$ssh_target" ]]; then
        if ! remote_run "test -x $STELOPS_REMOTE" >/dev/null 2>&1; then
            if [[ ! -x "$tool" ]]; then
                err "the ops tool is missing: $tool (build it: cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml)"
                return 1
            fi
            log "staging the ops tool on node $n"
            # shellcheck disable=SC2086
            scp -q $(node_scp_opts "$n") "$tool" "$ssh_target:$STELOPS_REMOTE" || {
                err "could not stage $tool on node $n"; return 1; }
            remote_run "chmod +x $STELOPS_REMOTE" || true
        fi
        tool="$STELOPS_REMOTE"
    else
        if [[ ! -x "$tool" ]]; then
            err "the ops tool is missing: $tool (build it: cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml)"
            return 1
        fi
    fi

    # --- 3. the checkpoint, read WITHOUT touching the node if possible ------
    # sled holds an EXCLUSIVE lock on the store while the node runs, so the
    # checkpoint is readable only with the node stopped. Try first: if the
    # node is already stopped, everything below happens without a restart.
    local cpout state
    state="$(probe_field "$n" service_state)"
    # The tool exits non-zero when the store is locked (the node is running);
    # that is a normal answer here, not a script failure.
    cpout="$(remote_run "$tool checkpoint $store" || true)"
    if [[ "$cpout" != *"height="* ]]; then
        # The store is locked: the node is running. The checkpoint can only be
        # read with the node stopped.
        if [[ "$force" != "--force" ]]; then
            warn "node $n is running, so the persisted lock cannot be read yet"
            warn "(sled locks the store while the node is up)."
            echo "  The plan: stop $svc, read the checkpoint, refuse if the lock is"
            echo "  not ahead of the peers, clear it, start $svc again."
            echo "  Re-run with: $0 lockclear $n --force"
            return 1
        fi
        log "stopping $svc (the store is locked while the node runs)"
        remote_run "$sysctl_cmd stop $svc" >/dev/null || true
        sleep 2
        cpout="$(remote_run "$tool checkpoint $store" || true)"
    fi

    echo "  checkpoint: $cpout"
    if [[ "$cpout" == *"NO_CHECKPOINT"* ]]; then
        warn "node $n has no persisted consensus lock — nothing to clear"
        [[ "$state" != "active" ]] && remote_run "$sysctl_cmd start $svc" >/dev/null
        return 0
    fi

    local lock_h lock_r
    lock_h="$(printf '%s' "$cpout" | sed -n 's/.*height=\([0-9]*\).*/\1/p')"
    lock_r="$(printf '%s' "$cpout" | sed -n 's/.*round=\([0-9]*\).*/\1/p')"

    # --- 4. the safety check -----------------------------------------------
    if [[ -n "$lock_h" && -n "$peer_tip" && "$peer_tip" != "0" ]]; then
        if (( lock_h <= peer_tip )); then
            err "REFUSING: node $n's lock is at height $lock_h, which is NOT ahead of the peer tip ($peer_tip)."
            err "         A node whose lock is behind its peers is not stuck because of the lock."
            [[ "$state" != "active" ]] && remote_run "$sysctl_cmd start $svc" >/dev/null
            return 1
        fi
        echo "  the lock is at height $lock_h (round $lock_r) — $((lock_h - peer_tip)) block(s) ahead of the peers"
    fi

    if [[ "$force" != "--force" ]]; then
        warn "REFUSING to clear the lock without --force."
        echo "  Re-run with: $0 lockclear $n --force"
        [[ "$state" != "active" ]] && remote_run "$sysctl_cmd start $svc" >/dev/null
        return 1
    fi

    log "clearing the consensus lock on node $n"
    local out
    out="$(remote_run "$tool clear-lock $store --force" || true)"
    echo "$out"
    if [[ "$out" != *"CLEARED"* ]]; then
        err "the lock was NOT cleared on node $n"
        remote_run "$sysctl_cmd start $svc" >/dev/null
        return 1
    fi

    log "starting $svc again"
    remote_run "$sysctl_cmd start $svc" >/dev/null
    sleep 5
    # the cached probe is stale now: the node was stopped and started
    unset "PROBE_CACHE[$n]"
    local st
    st="$(probe_field "$n" service_state || true)"
    echo "  service state after the clear: ${st:-?}"
    success "node $n: the stale consensus lock is cleared and the node is starting"
    return 0
}

# ==============================================================================
# `doctor [node]` — the single-node diagnosis (delegates to scripts/doctor.sh,
# which also runs standalone on a node).
# ==============================================================================
function do_doctor() {
    local n="${1:-}"
    local script="$STELL_SCRIPT_DIR/doctor.sh"
    if [[ ! -x "$script" ]]; then
        err "doctor script not found: $script"
        return 2
    fi
    if [[ -z "$n" ]]; then
        "$script" "${@:2}"
        return $?
    fi
    if ! is_known_node "$n"; then
        err "unknown node '$n' (known: $STELL_NODES)"
        return 2
    fi
    local dir svc scope ssh_target opts
    dir="$(node_conf "$n" DIR)"
    svc="$(node_conf "$n" SERVICE)"
    scope="$(node_conf "$n" SCOPE)"
    ssh_target="$(node_conf "$n" SSH)"
    opts="$(node_conf "$n" SSH_OPTS)"
    if [[ -z "$ssh_target" ]]; then
        "$script" --dir "$dir" --service "$svc" --scope "$scope" "${@:2}"
        return $?
    fi
    # The doctor is piped to the node's shell: it needs no installation there
    # and it cannot be a stale copy on the node.
    # shellcheck disable=SC2086
    timeout 300 ssh -o BatchMode=yes -o ConnectTimeout=8 $opts "$ssh_target" \
        "sh -s -- --dir $dir --service $svc --scope $scope ${*:2}" < "$script" 2>&1
}

usage() {
    cat <<EOF
stell-sync — Stellereum fast sync & cluster operations tool

USAGE
  $0 <command> [options]

COMMANDS
  status                  cluster dashboard (heights + explorer tip)
  health                  the operator health screen: validator set, shard heads,
                          chain tip, indexer tip, RPC latency, and the CLUSTER
                          TABLE (service state, inode usage, orphan chunks,
                          pubsub topic, consensus lock, binary hash, exit code)
  preflight               FAIL-CLOSED pre-deploy check. Refuses to deploy and
                          names every difference between the nodes (topic,
                          STELL_SHARDS, chain id, genesis root, timeouts,
                          retention, base fee, inodes, binary location, unit
                          state). Exit 1 = do not deploy.
  lockclear <node>        clear a stale consensus lock safely (stops the node,
                          clears the persisted checkpoint, starts it again).
                          Add --force to actually do it.
  topic <node>            print the pubsub topic a node uses
  doctor [node]           single-node diagnosis (config drift, inodes, orphan
                          chunks, consensus checkpoint, topic, binary, key
                          format, chain id). Use --json for machine output.
  sync [nodeA|nodeC|nodeD|local|all]   fast-sync from the HTTP snapshot
  auto-heal               re-sync a lagging node from the HTTP snapshot
  deploy                  ship a new binary to every node
  restart                 restart every node's service
  help                    this text

HEALTH OPTIONS
  --rpc URL               the RPC to health-check (default $HEALTH_RPC)
  --indexer URL           the indexer URL (default $HEALTH_INDEXER)
  --timeout SECONDS       per-call timeout (default $HEALTH_TIMEOUT)
  --no-orphans            skip the (slow) orphan chunk count
  --nodes "A B C D"       which nodes to probe (default: $STELL_NODES)

ENVIRONMENT
  STELL_CONF              the cluster topology file
                          (default /home/imm/stellereum-project/scripts/cluster-nodes.conf)
EOF
}

HEALTH_ORPHANS=1

case "$1" in
    health)
        shift || true
        # Optional overrides: --rpc URL --indexer URL
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --rpc)
                    HEALTH_RPC="$2"; shift 2 ;;
                --indexer)
                    HEALTH_INDEXER="$2"; shift 2 ;;
                --timeout)
                    HEALTH_TIMEOUT="$2"; shift 2 ;;
                --probe-timeout)
                    PROBE_TIMEOUT="$2"; shift 2 ;;
                --no-orphans)
                    HEALTH_ORPHANS=0; shift ;;
                --nodes)
                    STELL_NODES="$2"; shift 2 ;;
                *)
                    err "unknown option for health: $1"
                    exit 2 ;;
            esac
        done
        show_health
        ;;
    preflight)
        shift || true
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --no-orphans)
                    HEALTH_ORPHANS=0; shift ;;
                --nodes)
                    STELL_NODES="$2"; shift 2 ;;
                --probe-timeout)
                    PROBE_TIMEOUT="$2"; shift 2 ;;
                *)
                    err "unknown option for preflight: $1"
                    exit 2 ;;
            esac
        done
        show_preflight
        ;;
    lockclear)
        shift || true
        do_lockclear "$@"
        ;;
    topic)
        shift || true
        show_topic "$@"
        ;;
    doctor)
        shift || true
        do_doctor "$@"
        ;;
    status)
        show_status
        ;;
    push|sync|fast-sync)
        case "$2" in
            nodeA|a|A)
                http_sync_remote "Node A" "$NODE_A_SSH" "$NODE_A_DIR" "stell-nodeA.service"
                ;;
            nodeC|c|C)
                http_sync_remote "Node C" "$NODE_C_SSH" "$NODE_C_DIR" "stell-nodeC.service" "$NODE_C_SSH_OPTS"
                ;;
            nodeD|d|D)
                http_sync_remote "Node D" "$NODE_D_SSH" "$NODE_D_DIR" "stell-nodeD.service" "$NODE_D_SSH_OPTS"
                ;;
            nodeB|b|B|local)
                http_sync_local
                ;;
            all)
                http_sync_remote "Node A" "$NODE_A_SSH" "$NODE_A_DIR" "stell-nodeA.service"
                http_sync_remote "Node C" "$NODE_C_SSH" "$NODE_C_DIR" "stell-nodeC.service" "$NODE_C_SSH_OPTS"
                http_sync_remote "Node D" "$NODE_D_SSH" "$NODE_D_DIR" "stell-nodeD.service" "$NODE_D_SSH_OPTS"
                ;;
            *)
                echo "Usage: $0 sync [nodeA | nodeC | nodeD | local | all]"
                exit 1
                ;;
        esac
        ;;
    auto-heal)
        auto_heal
        ;;
    deploy)
        deploy_binaries
        ;;
    restart)
        log "Restarting cluster services in parallel..."
        ssh $NODE_A_SSH "systemctl restart stell-nodeA.service" &
        ssh $NODE_D_SSH "systemctl restart stell-nodeD.service" &
        ssh $NODE_C_SSH_OPTS $NODE_C_SSH "systemctl restart stell-nodeC.service" &
        systemctl --user restart stell-nodeB.service &
        wait
        success "All cluster services restarted!"
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
