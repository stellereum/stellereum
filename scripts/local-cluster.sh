#!/usr/bin/env bash
# ==============================================================================
# local-cluster.sh — quality LOCAL simulator: N validators on ONE machine.
#
# Legit dev tests (finality, stalls, chaos) without multiple VPS servers.
# Everything lives under run/cluster/ (gitignored). NEVER touches
# multinode/, live configs, /root/*, or the network.
#
# Two-phase flow (solves the chicken-and-egg: configs need peer node-ids
# before first boot, but keys generate on first boot):
#   Phase 1: `stellereum keys init` per node (idempotent, no node boot),
#            collect id/ed/falcon from the NODE IDENTITY line.
#   Phase 2: write full node.yaml per node (ALL ids in validators:, peers =
#            every OTHER node), then boot all fresh with STELL_NEW_CHAIN=1.
#
# Usage:
#   ./scripts/local-cluster.sh up [N] [--shards 0,1]  # default N=3, single-shard unless --shards given
#   ./scripts/local-cluster.sh up2 [N]                # shortcut: same as up N --shards 0,1 (2-shard XPC demo mode)
#   ./scripts/local-cluster.sh status
#   ./scripts/local-cluster.sh stop [i] | start [i] | restart [i]
#   ./scripts/local-cluster.sh down        # stop all
#   ./scripts/local-cluster.sh reset       # wipe data, keep keys, fresh boot (preserves shard mode from env.i)
#   ./scripts/local-cluster.sh chaos       # stop node3 for 60s, then return
# Two-shard (XPC/2PC demo) mode: STELL_SHARDS=0,1 preserved at boot (single process
# drives masterchain + workchain 1 over one P2P port per node; topics disjoint by
# shard id, no extra ports), STELL_XPC_ACTIVATION_HEIGHT=5 in env.i so 2PC is
# reachable in minutes, workchain funded from the same faucet seed + DEV_UNSAFE flag.
# See scripts/local-cluster.md "2-shard mode" for commands/env deltas.
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER="$ROOT/run/cluster"

P2P_BASE="${STELL_LOCAL_P2P_BASE:-19410}"        # P2P listen/advertise base: 19410+i (127.0.0.1)
RPC_BASE="${STELL_LOCAL_RPC_BASE:-18645}"        # JSON-RPC base: 18645+i (NOTE: 18545 is taken on this
                                                 # dev box by an ssh tunnel, so NOT 18545+i)
EXP_BASE="${STELL_LOCAL_EXP_BASE:-18080}"        # explorer/gateway base: 18080+i (default 8080 would clash)
FAUCET_KEY="1111111111111111111111111111111111111111111111111111111111111111"
CHAIN_NOTE="chain id default 5757 on all nodes (STELL_CHAIN_ID left unset)"
XPC_HEIGHT=5             # 2-shard mode only: STELL_XPC_ACTIVATION_HEIGHT (low so 2PC reachable in minutes)
SHARDS_2="0,1"           # opt-in 2-shard registry: one process drives masterchain + workchain 1

# --- binary: prefer debug, else release; NEVER build here ---------------------
resolve_bin() {
    if [[ -n "${STELL_BIN:-}" && -x "${STELL_BIN:-}" ]]; then
        echo "$STELL_BIN"
        return 0
    fi
    for cand in \
        "$ROOT/target/release/stellereum" \
        "$ROOT/target/debug/stellereum" \
        "$ROOT/stellereum/target/debug/stellereum" \
        "$ROOT/stellereum/target/release/stellereum"; do
        if [[ -x "$cand" ]]; then
            echo "$cand"
            return 0
        fi
    done
    local which_bin
    which_bin="$(which stellereum 2>/dev/null || true)"
    if [[ -n "$which_bin" && -x "$which_bin" ]]; then
        echo "$which_bin"
        return 0
    fi
    echo "[local-cluster] FATAL: no stellereum binary found." >&2
    echo "  Looked in stellereum/target/{debug,release}/stellereum and PATH." >&2
    echo "  Build it first (e.g. cargo build -p stellereum); this script never builds." >&2
    return 1
}

# --- ports: fail loudly if occupied (ss check before binding) -----------------
ports_free_for() {
    local n="$1" i p2p rpc exp
    for ((i = 1; i <= n; i++)); do
        p2p=$((P2P_BASE + i)); rpc=$((RPC_BASE + i)); exp=$((EXP_BASE + i))
        for port in "$p2p" "$rpc" "$exp"; do
            if ss -ltn 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; then
                echo "[local-cluster] FATAL: port $port is already in use (node$i needs" \
                    "p2p=$p2p rpc=$rpc explorer=$exp). Free it or pick another base." >&2
                return 1
            fi
        done
    done
}

node_dir() { echo "$CLUSTER/node$1"; }

# --- phase 1: keygen via the real CLI (same mechanism as `run`) ---------------
# Prints: <id> <ed> <pq_pub> <falcon>
keygen_node() {
    local bin="$1" i="$2" dir
    dir="$(node_dir "$i")"
    mkdir -p "$dir/keys" "$dir/data"
    if [[ -f "$dir/keys/e2e.key" ]] && (( $(wc -c < "$dir/keys/e2e.key") <= 64 )); then
        echo "[local-cluster] removing stale pre-PQ $dir/keys/e2e.key" >&2
        rm -f "$dir/keys/e2e.key"
    fi
    local out
    out="$(STELL_KEY_PLAINTEXT=1 "$bin" keys init --keys-dir "$dir/keys" 2>&1)" || {
        echo "[local-cluster] FATAL: keys init failed for node$i:" >&2
        echo "$out" >&2
        return 1
    }
    local ident
    ident="$(echo "$out" | grep -oE 'NODE IDENTITY: .*' || true)"
    if [[ -z "$ident" ]]; then
        echo "[local-cluster] FATAL: no NODE IDENTITY line for node$i. Output:" >&2
        echo "$out" >&2
        return 1
    fi
    local id ed pq_pub falcon
    id="$(echo "$ident" | grep -oE 'id=[^ ]+' | cut -d= -f2)"
    ed="$(echo "$ident" | grep -oE 'ed=[^ ]+' | cut -d= -f2)"
    pq_pub="$(echo "$ident" | grep -oE 'pq_pub=[^ ]+' | cut -d= -f2)"
    falcon="$(echo "$ident" | grep -oE 'falcon=[^ ]+' | cut -d= -f2)"
    if [[ -z "$id" || -z "$ed" || -z "$pq_pub" || -z "$falcon" ]]; then
        echo "[local-cluster] FATAL: could not parse NODE IDENTITY for node$i: $ident" >&2
        return 1
    fi
    echo "$id $ed $pq_pub $falcon"
}

# --- phase 2: write node.yaml + env.i ------------------------------------------
# Args: write_configs <n> <shards> <stanza1> ... <stanzaN>
#   shards = "" (single-shard) or "0,1" (2-shard XPC demo mode).
write_configs() {
    local n="$1"; shift
    local shards="$1"; shift
    # remaining args: per-node "id ed pq_pub falcon" in order 1..n
    local -a IDS=() EDS=() PQS=() FALCONS=()
    local i
    for ((i = 1; i <= n; i++)); do
        read -r id ed pq_pub falcon <<< "$1"; shift
        IDS+=("$id"); EDS+=("$ed"); PQS+=("$pq_pub"); FALCONS+=("$falcon")
    done
    # STELL_PEER_PQ_KEYS: identical on every node (ed:pq for ALL members).
    local pq_keys=""
    for ((i = 0; i < n; i++)); do
        [[ -n "$pq_keys" ]] && pq_keys+=","
        pq_keys+="${EDS[$i]}:${FALCONS[$i]}"
    done
    for ((i = 1; i <= n; i++)); do
        local dir p2p rpc exp
        dir="$(node_dir "$i")"
        p2p=$((P2P_BASE + i)); rpc=$((RPC_BASE + i)); exp=$((EXP_BASE + i))
        {
            echo "name: local$i"
            echo "listen: \"127.0.0.1:$p2p\""
            echo "advertise: \"127.0.0.1:$p2p\""
            echo "validators:"
            for ((j = 0; j < n; j++)); do
                echo "  - \"${IDS[$j]}\""
            done
            echo "peers:"
            for ((j = 1; j <= n; j++)); do
                if [[ "$j" -eq "$i" ]]; then continue; fi
                local k=$((j - 1)) jp=$((P2P_BASE + j))
                echo "  - name: local$j"
                echo "    ed-pub: \"${EDS[$k]}\""
                echo "    pq-pub: \"${PQS[$k]}\""
                echo "    endpoints: [\"127.0.0.1:$jp\"]"
                echo "    allow: [\"*\"]"
            done
        } > "$dir/node.yaml"
        {
            echo "# local-cluster env for node$i (sourced with 'set -a')."
            if [[ "$shards" == "$SHARDS_2" ]]; then
                echo "# 2-shard XPC demo mode: STELL_SHARDS=0,1 (one process drives both shards over"
                echo "# one P2P port; topics disjoint by shard, no extra ports). Workchain funded from"
                echo "# the same faucet seed + DEV_UNSAFE flag; XPC active from height $XPC_HEIGHT."
                echo "STELL_SHARDS=$SHARDS_2"
                echo "STELL_XPC_ACTIVATION_HEIGHT=$XPC_HEIGHT"
            else
                echo "# Single-shard on purpose: NO STELL_SHARDS (plain topics, no workchain)."
            fi
            echo "STELL_KEY_PLAINTEXT=1"
            echo "STELL_NEW_CHAIN=1"
            echo "STELL_FAUCET_KEY=$FAUCET_KEY"
            echo "STELL_DEV_UNSAFE_TESTKEY=1"
            echo "STELL_LEGACY_GENESIS_ROOT=1"
            echo "STELL_PURE_PQ=1"
            echo "STELL_PEER_PQ_KEYS=$pq_keys"
            echo "STELL_ROUND_TIMEOUT_MS=10000"
            echo "STELL_BROADCAST_JOIN_MS=2000"
            echo "STELL_CATCHUP_BUDGET_MS=8000"
            echo "STELL_RPC_LISTEN=127.0.0.1:$rpc"
            echo "STELL_EXPLORER_LISTEN=127.0.0.1:$exp"
        } > "$dir/env.$i"
    done
    if [[ "$shards" == "$SHARDS_2" ]]; then
        echo "[local-cluster] wrote configs for $n nodes, 2-shard mode (STELL_SHARDS=$SHARDS_2, XPC_HEIGHT=$XPC_HEIGHT)."
    else
        echo "[local-cluster] wrote configs for $n nodes (validators: all members listed)."
    fi
}

boot_node() {
    local bin="$1" i="$2" dir
    dir="$(node_dir "$i")"
    if [[ -f "$dir/node.pid" ]] && kill -0 "$(cat "$dir/node.pid")" 2>/dev/null; then
        echo "[local-cluster] node$i already running (pid $(cat "$dir/node.pid"))."
        return 0
    fi
    if [[ ! -f "$dir/env.$i" || ! -f "$dir/node.yaml" ]]; then
        echo "[local-cluster] FATAL: node$i has no config (run '$0 up' first)." >&2
        return 1
    fi
    (
        cd "$dir"
        set -a
        # shellcheck disable=SC1091
        source "$dir/env.$i"
        set +a
        # Single-shard guard: keep single-shard even if the caller exported STELL_SHARDS,
        # but PRESERVE it when this node's env.i opts into 2-shard mode (XPC demo).
        # Belt26693 single-shard default; 2-shard opt-in via `up --shards 0,1` / `up2`.
        if grep -q '^STELL_SHARDS=' "$dir/env.$i" 2>/dev/null; then
            : # 2-shard mode: keep STELL_SHARDS + STELL_XPC_ACTIVATION_HEIGHT from env.i
        else
            unset STELL_SHARDS || true
        fi
        unset STELL_OBSERVER STELL_DNS_SEEDS || true
        # One process drives both shards in 2-shard mode (main flow pinned to
        # masterchain; workchain 1 spawns as an in-process extra over the SAME
        # infnode node/P2P port — no extra ports; cf. run-observer.sh
        # STELL_SHARDS=0,1 + `run --shard 0`). Same `--shard 0` in both modes.
        nohup "$bin" run --config node.yaml --shard 0 >> live.log 2>&1 &
        echo $! > node.pid
    )
    echo "[local-cluster] node$i booted (pid $(cat "$dir/node.pid"), p2p=127.0.0.1:$((P2P_BASE + i)), rpc=127.0.0.1:$((RPC_BASE + i)))."
}

stop_node() {
    local i="$1" dir pid
    dir="$(node_dir "$i")"
    [[ -f "$dir/node.pid" ]] || { echo "[local-cluster] node$i not running (no pid file)."; return 0; }
    pid="$(cat "$dir/node.pid")"
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.5
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        echo "[local-cluster] node$i stopped (was pid $pid)."
    else
        echo "[local-cluster] node$i already dead (stale pid $pid)."
    fi
    rm -f "$dir/node.pid"
}

node_count() {
    local c=0 d
    for d in "$CLUSTER"/node*/; do
        [[ -d "$d" ]] || continue
        c=$((c + 1))
    done
    echo "$c"
}

max_finalized() {
    grep -oE 'FINALIZED block #[0-9]+' "$1" 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1
}

node_epoch() {
    grep -oE 'chain epoch [0-9a-f]+' "$1" 2>/dev/null | head -1 | awk '{print $3}'
}

rpc_block() {
    local port="$1" out hex
    out="$(curl -s -m 5 -X POST -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
        "http://127.0.0.1:$port" 2>/dev/null || true)"
    hex="$(echo "$out" | grep -oE '"result":"0x[0-9a-fA-F]+"' | head -1 | grep -oE '0x[0-9a-fA-F]+' || true)"
    if [[ -z "$hex" ]]; then echo "n/a"; else echo "$((hex))"; fi
}

# --- wait for first FINALIZED on every node, then assert common height+epoch --
wait_finalized() {
    local n="$1" timeout="${2:-120}" i elapsed=0 ok
    echo "[local-cluster] waiting up to ${timeout}s for first FINALIZED on all $n nodes..."
    while ((elapsed < timeout)); do
        ok=1
        for ((i = 1; i <= n; i++)); do
            if ! grep -q 'FINALIZED block #' "$(node_dir "$i")/live.log" 2>/dev/null; then
                ok=0; break
            fi
        done
        if ((ok == 1)); then break; fi
        sleep 2; elapsed=$((elapsed + 2))
    done
    if ((ok != 1)); then
        echo "[local-cluster] FATAL: timeout after ${timeout}s; nodes without FINALIZED:" >&2
        for ((i = 1; i <= n; i++)); do
            grep -q 'FINALIZED block #' "$(node_dir "$i")/live.log" 2>/dev/null || echo "  node$i" >&2
        done
        return 1
    fi
    # Epoch MUST be identical (genesis fingerprint, deterministic from same inputs).
    local epoch0="" e
    for ((i = 1; i <= n; i++)); do
        e="$(node_epoch "$(node_dir "$i")/live.log")"
        if [[ -z "$e" ]]; then
            echo "[local-cluster] FATAL: node$i has FINALIZED blocks but no 'chain epoch' line." >&2
            return 1
        fi
        if [[ -z "$epoch0" ]]; then epoch0="$e"; fi
        if [[ "$e" != "$epoch0" ]]; then
            echo "[local-cluster] FATAL: epoch split: node1=$epoch0 node$i=$e (genesis diverged)." >&2
            return 1
        fi
    done
    # SAME heights: the intersection of finalized-height sets must be non-empty.
    local common_tmp prev_tmp
    common_tmp="$(mktemp)"; prev_tmp="$(mktemp)"
    grep -oE 'FINALIZED block #[0-9]+' "$(node_dir 1)/live.log" | grep -oE '[0-9]+' | sort -nu > "$common_tmp"
    for ((i = 2; i <= n; i++)); do
        grep -oE 'FINALIZED block #[0-9]+' "$(node_dir "$i")/live.log" | grep -oE '[0-9]+' | sort -nu > "$prev_tmp"
        grep -Fxf "$common_tmp" "$prev_tmp" > "$prev_tmp.common" || true
        mv "$prev_tmp.common" "$common_tmp"
    done
    rm -f "$prev_tmp"
    if [[ ! -s "$common_tmp" ]]; then
        rm -f "$common_tmp"
        echo "[local-cluster] FATAL: nodes finalized DISJOINT height sets (no common height)." >&2
        return 1
    fi
    local ncommon common_max
    ncommon="$(wc -l < "$common_tmp")"
    common_max="$(tail -1 "$common_tmp")"
    rm -f "$common_tmp"
    echo "[local-cluster] OK: epoch $epoch0 identical on all $n nodes; $ncommon common FINALIZED height(s), max #$common_max."
}

# --- 2-shard helpers ----------------------------------------------------------
shard_mode() {
    grep -oE '^STELL_SHARDS=[^ ]+' "$CLUSTER/node1/env.1" 2>/dev/null | cut -d= -f2 || true
}

wait_sharded_ready() {
    # After generic FINALIZED convergence, assert BOTH shards run in-process:
    # workchain genesis + XPC ACTIVE lines on every node, plus per-shard stores.
    # NOTE: FINALIZED lines do not carry a shard id (single log file for both
    # consensus instances), so the combined count is ~2x single-shard tempo;
    # per-shard stores + genesis/XPC lines are the shard-liveness proof.
    local n="$1" i missing=0
    for ((i = 1; i <= n; i++)); do
        if ! grep -q 'workchain genesis' "$(node_dir "$i")/live.log" 2>/dev/null; then
            echo "[local-cluster] FATAL: node$i shows FINALIZED but no '[shard 1] workchain genesis' (workchain extra never started)." >&2
            missing=1
        fi
        if ! grep -q 'cross-shard 2PC ACTIVE from height' "$(node_dir "$i")/live.log" 2>/dev/null; then
            echo "[local-cluster] FATAL: node$i missing 'cross-shard 2PC ACTIVE' (STELL_XPC_ACTIVATION_HEIGHT not wired)." >&2
            missing=1
        fi
        if [[ ! -d "$(node_dir "$i")/data/store-shard1" ]]; then
            echo "[local-cluster] FATAL: node$i missing data/store-shard1 (workchain store never opened)." >&2
            missing=1
        fi
    done
    if ((missing != 0)); then return 1; fi
    echo "[local-cluster] OK: 2-shard mode live on all $n nodes (masterchain store + store-shard1, XPC ACTIVE, shared P2P 19410+i, topics shard-scoped)."
}

cmd_up() {
    local n="3" shards="" a bin i
    for a in "$@"; do
        case "$a" in
            --shards=*) shards="${a#--shards=}" ;;
            --shards) shards="$SHARDS_2" ;;
            0,1) shards="0,1" ;;
            [1-9]*) n="$a" ;;
            *) echo "[local-cluster] FATAL: unknown up arg '$a' (usage: up [N] [--shards 0,1])" >&2; return 1 ;;
        esac
    done
    # Bare "0,1" without flag already handled; "--shards" without value means 0,1.
    if [[ "$shards" != "" && "$shards" != "$SHARDS_2" ]]; then
        echo "[local-cluster] FATAL: only --shards $SHARDS_2 is supported (got '$shards')." >&2
        return 1
    fi
    bin="$(resolve_bin)" || return 1
    echo "[local-cluster] binary: $bin"
    if [[ "$shards" == "$SHARDS_2" ]]; then
        echo "[local-cluster] mode: 2-shard (STELL_SHARDS=$SHARDS_2, XPC_HEIGHT=$XPC_HEIGHT, same P2P 19410+i, topics shard-scoped)"
    else
        echo "[local-cluster] mode: single-shard (plain topics, no workchain)"
    fi
    ports_free_for "$n" || return 1
    mkdir -p "$CLUSTER"
    echo "[local-cluster] phase 1: keygen for $n nodes..."
    local -a stanzas=()
    for ((i = 1; i <= n; i++)); do
        stanzas+=("$(keygen_node "$bin" "$i")") || return 1
        echo "  node$i: $(echo "${stanzas[$((i - 1))]}" | cut -d' ' -f1)"
    done
    echo "[local-cluster] phase 2: configs..."
    write_configs "$n" "$shards" "${stanzas[@]}"
    for ((i = 1; i <= n; i++)); do
        : > "$(node_dir "$i")/live.log"
        rm -f "$(node_dir "$i")/node.pid"
        rm -rf "$(node_dir "$i")/data"
        mkdir -p "$(node_dir "$i")/data"
        boot_node "$bin" "$i"
    done
    wait_finalized "$n" 120 || return 1
    if [[ "$shards" == "$SHARDS_2" ]]; then
        wait_sharded_ready "$n" || return 1
    fi
    cmd_status
}

cmd_status() {
    local n i mode
    n="$(node_count)"
    if ((n == 0)); then echo "[local-cluster] no nodes under $CLUSTER."; return 0; fi
    mode="$(shard_mode || true)"
    if [[ -n "$mode" ]]; then
        echo "[local-cluster] shard mode: STELL_SHARDS=$mode (2-shard: one process/node, shared P2P, topics shard-scoped; FINALIZED counts cover BOTH shards)"
    else
        echo "[local-cluster] shard mode: single-shard (no STELL_SHARDS)"
    fi
    printf '%-7s %-7s %-10s %-8s %-18s %-12s %s\n' NODE ALIVE FINALS HEIGHT EPOCH RPC_BLOCK RPC
    for ((i = 1; i <= n; i++)); do
        local dir alive finals height epoch rpc
        dir="$(node_dir "$i")"
        [[ -d "$dir" ]] || continue
        alive="no"
        if [[ -f "$dir/node.pid" ]] && kill -0 "$(cat "$dir/node.pid")" 2>/dev/null; then
            alive="yes($(cat "$dir/node.pid"))"
        fi
        finals="$(grep -c 'FINALIZED block #' "$dir/live.log" 2>/dev/null || true)"
        height="$(max_finalized "$dir/live.log" || true)"
        [[ -z "$height" ]] && height="-"
        epoch="$(node_epoch "$dir/live.log" || true)"
        [[ -z "$epoch" ]] && epoch="-"
        rpc="$(rpc_block $((RPC_BASE + i)))"
        printf '%-7s %-7s %-10s %-8s %-18s %-12s %s\n' \
            "node$i" "$alive" "$finals" "#$height" "$epoch" "$rpc" "127.0.0.1:$((RPC_BASE + i))"
    done
}

cmd_chaos() {
    local n target bin
    n="$(node_count)"
    if ((n == 0)); then echo "[local-cluster] nothing to chaos (no nodes)."; return 1; fi
    bin="$(resolve_bin)" || return 1
    if ((n >= 3)); then target=3; else target="$n"; fi
    echo "[local-cluster] chaos: stopping node$target for 60s."
    echo "  Expectation: with N=3 (unanimous quorum) the chain STALLS while node$target is"
    echo "  down — only round/timeout movement in survivor logs, NO liveness asserted."
    echo "  With N>=4 the remaining validators keep finalizing. On return, node$target"
    echo "  catches up via the blind-QC-probe path."
    local before
    before="$(stat -c %s "$(node_dir 1)/live.log" 2>/dev/null || echo 0)"
    stop_node "$target"
    echo "[local-cluster] node$target down; sleeping 60s..."
    sleep 60
    local s i
    for ((i = 1; i <= n; i++)); do
        if [[ "$i" -eq "$target" ]]; then continue; fi
        s="$(stat -c %s "$(node_dir "$i")/live.log" 2>/dev/null || echo 0)"
        echo "  survivor node$i log size now ${s}B (round movement expected even under stall)."
    done
    if ((n < 4)); then
        echo "  N=$n < 4: stall expected, liveness NOT asserted (by design)."
    fi
    boot_node "$bin" "$target"
    echo "[local-cluster] node$target restarted; waiting up to 180s for NEW finalization post-restart..."
    # NOTE: live.log is NOT wiped on restart, so a bare `grep -q FINALIZED`
    # would match pre-kill lines and return instantly. Snapshot the baseline
    # count and wait for growth instead (returnee catching up / chain resuming).
    local base_count now_count elapsed=0
    base_count="$(grep -c 'FINALIZED block #' "$(node_dir "$target")/live.log" 2>/dev/null || true)"
    while ((elapsed < 180)); do
        now_count="$(grep -c 'FINALIZED block #' "$(node_dir "$target")/live.log" 2>/dev/null || true)"
        if ((now_count > base_count)); then
            break
        fi
        sleep 2; elapsed=$((elapsed + 2))
    done
    now_count="$(grep -c 'FINALIZED block #' "$(node_dir "$target")/live.log" 2>/dev/null || true)"
    if ((now_count <= base_count)); then
        echo "[local-cluster] WARN: node$target finalized nothing new within 180s of restart" \
            "(base=$base_count, now=$now_count). See $(node_dir "$target")/live.log." >&2
    else
        echo "[local-cluster] OK: node$target finalized $((now_count - base_count)) new block(s) post-restart."
    fi
    echo "[local-cluster] chaos done. Status:"
    cmd_status
    echo "[local-cluster] check the returnee caught up: its height should approach peers' (status above)."
}

cmd_reset() {
    local n bin i
    n="$(node_count)"
    if ((n == 0)); then echo "[local-cluster] nothing to reset."; return 1; fi
    bin="$(resolve_bin)" || return 1
    for ((i = 1; i <= n; i++)); do stop_node "$i"; done
    for ((i = 1; i <= n; i++)); do
        rm -rf "$(node_dir "$i")/data"
        mkdir -p "$(node_dir "$i")/data"
        : > "$(node_dir "$i")/live.log"
    done
    echo "[local-cluster] data wiped (keys/configs kept); fresh boot with STELL_NEW_CHAIN=1..."
    for ((i = 1; i <= n; i++)); do boot_node "$bin" "$i"; done
    wait_finalized "$n" 120 || return 1
    cmd_status
}

usage() {
    sed -n '2,/^# =\+$/p' "$0" | sed 's/^# \{0,1\}//'
}

main() {
    local cmd="${1:-help}"
    case "$cmd" in
        up) shift; cmd_up "$@" ;;
        up2) shift; cmd_up "$@" --shards=0,1 ;;
        status) cmd_status ;;
        stop)
            if [[ -n "${2:-}" ]]; then stop_node "$2"; else
                local n i; n="$(node_count)"
                for ((i = 1; i <= n; i++)); do stop_node "$i"; done
            fi ;;
        start)
            if [[ -z "${2:-}" ]]; then echo "usage: $0 start <i>" >&2; return 1; fi
            local bin; bin="$(resolve_bin)" || return 1
            boot_node "$bin" "$2" ;;
        restart)
            if [[ -z "${2:-}" ]]; then echo "usage: $0 restart <i>" >&2; return 1; fi
            local bin2; bin2="$(resolve_bin)" || return 1
            stop_node "$2"; boot_node "$bin2" "$2" ;;
        down)
            local n2 i2; n2="$(node_count)"
            for ((i2 = 1; i2 <= n2; i2++)); do stop_node "$i2"; done ;;
        reset) cmd_reset ;;
        chaos) cmd_chaos ;;
        help|--help|-h|*) usage ;;
    esac
}

main "$@"
