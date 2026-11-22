#!/usr/bin/env bash
# ==============================================================================
# upgrade_drill.sh — run a REAL software-upgrade rehearsal on a throwaway
# local cluster (loopback ports, temp dirs under /tmp/opencode).
#
# This is the executable counterpart to docs/UPGRADE_AND_RECOVERY.md §1.2 and
# §2.  It never touches a live cluster: every socket is allocated on
# 127.0.0.1, every data directory lives under /tmp/opencode, and cleanup is
# trap-driven.
#
# Modes
#   --mode manual    Works TODAY.  Start N validators, produce traffic, stop
#                    all of them the way an operator would (SIGTERM), swap the
#                    binary (a second copy from the same tree + a version
#                    marker), restart, and prove:
#                      * heights resumed and all nodes agree on a common height
#                      * the historical block at the pre-stop height is
#                        byte-identical after restart (no double-apply/reorg)
#                      * the upgraded process is really the new binary/marker
#                      * RTO = first SIGTERM -> first NEW finalized block
#
#   --mode onchain   For when UPGRADE_EXEC_ACTIVATION_HEIGHT is no longer
#                    u64::MAX.  While the gate is closed this mode FAILS
#                    CLOSED with "on-chain execution is gated" and starts no
#                    cluster.  When open it drives a block-path SoftwareUpgrade
#                    through an operator-supplied submitter, waits for the
#                    halt marker + exit 42, proves the drain happened, proves
#                    the OLD binary refuses to start on the marker, installs
#                    the staged binary, clears the marker, and verifies the
#                    chain resumes at the planned height.
#
# Safety contract
#   * --local-only is REQUIRED.  The script also audits every generated
#     endpoint and refuses anything that is not loopback/private.
#   * Ports are allocated dynamically and bind-checked; live ports
#     (18645+i / 18080+i / 19410+i, nodeB, multinode/) are never touched.
#   * No faucet/staking/governance call is made to anything except the RPC
#     and explorer ports this run allocated.  The only governance call in
#     manual mode is a plain PQ transfer used as traffic.
#   * Every process this script starts is killed on EXIT/INT/TERM.
#
# Machine-readable result (last line on stdout, also in $RUN_ROOT/summary.txt):
#   DRILL_RESULT=PASS mode=manual nodes=3 rto_ms=... rto_seconds=... ...
#
# Exit: 0 = PASS, 1 = FAIL (including the gated on-chain mode).
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Defaults / globals
# ---------------------------------------------------------------------------
MODE=""
LOCAL_ONLY=0
NODES="${DRILL_NODES:-3}"
OLD_BIN="${STELL_BIN:-}"
NEW_BIN=""
READY_TIMEOUT=180
RESUME_TIMEOUT=180
STOP_TIMEOUT=120
RTO_BUDGET_MS=180000
MIN_HEIGHT=12
TRAFFIC_TXS=2
KEEP=1
PURGE_ON_PASS=0
RUN_ROOT=""
B3=""
LIVE_BIN=""
FAUCET_KEY="1111111111111111111111111111111111111111111111111111111111111111"
RECIPIENT_SEED="3333333333333333333333333333333333333333333333333333333333333333"
OLD_LABEL=""
NEW_LABEL=""
PLAN_NAME=""
PLAN_HEIGHT=""
STAGED_BIN=""
SUBMIT_CMD=""
ONCHAIN_TIMEOUT=900

P2P_BASE=0
RPC_BASE=0
EXP_BASE=0

RESULT="FAIL"
REASON=""
RTO_MS=0
PRE_HEIGHT=0
POST_HEIGHT=0
COMMON_ROOT=""
RUNNING_DIR=""
GATE_VALUE=""
GATE_OPEN=0

declare -a NODE_PIDS=()
declare -a NODE_ALIVE=()
declare -a NODE_EXIT=()
declare -a CID=()
declare -a ED=()
declare -a PQ=()
declare -a FAL=()

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------
log()  { printf '[drill] %s\n' "$*"; }
warn() { printf '[drill] WARN: %s\n' "$*" >&2; }
die()  { printf '[drill] FATAL: %s\n' "$*" >&2; exit 2; }

now_ms() { date +%s%3N; }
ms_to_s() {
    local ms="$1"
    printf '%d.%03d' $((ms / 1000)) $((ms % 1000))
}
sha256_of() { sha256sum "$1" | awk '{print $1}'; }

usage() {
    sed -n '2,46p' "$0" | sed 's/^# \{0,1\}//'
}

node_dir() { printf '%s/node%s' "$RUN_ROOT" "$1"; }
rpc_url()  { printf 'http://127.0.0.1:%s' "$((RPC_BASE + $1))"; }
exp_url()  { printf 'http://127.0.0.1:%s' "$((EXP_BASE + $1))"; }
p2p_port() { printf '%s' "$((P2P_BASE + $1))"; }

rpc_post() {
    # rpc_post <node> <method> <params-json>
    local i="$1" method="$2" params="$3"
    curl -s -m 8 -X POST -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
        "$(rpc_url "$i")" 2>/dev/null || true
}

rpc_height() {
    local out hex
    out="$(rpc_post "$1" eth_blockNumber '[]')"
    hex="$(printf '%s' "$out" | grep -oE '"result":"0x[0-9a-fA-F]+"' | head -1 | cut -d'"' -f4 || true)"
    if [[ -z "$hex" ]]; then echo ""; return 0; fi
    printf '%d' "$((16#${hex#0x}))"
}

rpc_root() {
    local out
    out="$(rpc_post "$1" stell_getStateRoot '[]')"
    printf '%s' "$out" | grep -oE '"result":"0x[0-9a-fA-F]+"' | head -1 | cut -d'"' -f4 || true
}

rpc_balance_nonce() {
    # rpc_balance_nonce <node> <address> -> "balance nonce"
    local out bal nonce
    out="$(rpc_post "$1" stell_getBalance "{\"address\":\"$2\"}")"
    bal="$(printf '%s' "$out" | grep -oE '"balance":"[0-9]+"' | head -1 | cut -d'"' -f4 || true)"
    nonce="$(printf '%s' "$out" | grep -oE '"nonce":[0-9]+' | head -1 | cut -d: -f2 || true)"
    printf '%s %s' "${bal:-}" "${nonce:-}"
}

rpc_block_hash() {
    # Durable header store (`stell_getBlock`), unlike the in-memory
    # finalized-header window this survives a restart and can answer for a
    # height finalized BEFORE the restart.
    local out
    out="$(rpc_post "$1" stell_getBlock "{\"height\":$2}")"
    printf '%s' "$out" | grep -oE '"hash":"[0-9a-fA-F]+"' | head -1 | cut -d'"' -f4 || true
}

rpc_historical_root() {
    # Snapshot-history root (only for heights covered by a snapshot).  Used
    # as an ADDITIONAL check when available, never as the only proof.
    local out
    out="$(rpc_post "$1" stell_getHistoricalRoot "{\"height\":$2}")"
    printf '%s' "$out" | grep -oE '"state_root":"[0-9a-fA-F]+"' | head -1 | cut -d'"' -f4 || true
}

rpc_receipt_block() {
    local out
    out="$(rpc_post "$1" eth_getTransactionReceipt "[\"0x$2\"]")"
    printf '%s' "$out" | grep -oE '"blockNumber":"0x[0-9a-fA-F]+"' | head -1 | cut -d'"' -f4 || true
}

metric_value() {
    # metric_value <node> <name>; empty when the explorer is not serving yet.
    local line
    line="$(curl -s -m 5 "$(exp_url "$1")/metrics" 2>/dev/null | grep -E "^$2 " | head -1 || true)"
    [[ -n "$line" ]] && printf '%s' "$line" | awk '{print $2}' || true
}

wait_metrics() {
    local i deadline
    deadline=$(( $(now_ms) + 30000 ))
    while (( $(now_ms) < deadline )); do
        local ok=1
        for i in $(seq 1 "$NODES"); do
            [[ -n "$(metric_value "$i" stell_consensus_height)" ]] || { ok=0; break; }
        done
        [[ "$ok" == "1" ]] && return 0
        sleep 0.25
    done
    return 1
}

port_free() {
    python3 - "$1" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
}

is_private_or_loopback() {
    local host="$1"
    [[ "$host" == "localhost" ]] && return 0
    [[ "$host" == "::1" ]] && return 0
    [[ "$host" =~ ^127\. ]] && return 0
    [[ "$host" =~ ^10\. ]] && return 0
    [[ "$host" =~ ^192\.168\. ]] && return 0
    [[ "$host" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
    return 1
}

# ---------------------------------------------------------------------------
# Cleanup / result
# ---------------------------------------------------------------------------
cleanup() {
    local i pid
    trap - EXIT INT TERM
    for i in "${!NODE_PIDS[@]}"; do
        pid="${NODE_PIDS[$i]:-}"
        [[ -z "$pid" ]] && continue
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    for i in "${!NODE_PIDS[@]}"; do
        pid="${NODE_PIDS[$i]:-}"
        [[ -z "$pid" ]] && continue
        for _ in $(seq 1 100); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
    done
    NODE_PIDS=()
}

write_summary() {
    local result="$1" reason="${2:-}"
    local line
    line="DRILL_RESULT=$result mode=${MODE:-unset} nodes=$NODES rto_ms=$RTO_MS rto_seconds=$(ms_to_s "$RTO_MS") pre_height=$PRE_HEIGHT post_height=$POST_HEIGHT state_root=${COMMON_ROOT:-} gate=${GATE_VALUE:-unknown} reason=\"${reason}\" log_dir=$RUN_ROOT"
    printf '%s\n' "$line" | tee "$RUN_ROOT/summary.txt"
    {
        echo "mode=$MODE"
        echo "result=$result"
        echo "nodes=$NODES"
        echo "rto_ms=$RTO_MS"
        echo "rto_seconds=$(ms_to_s "$RTO_MS")"
        echo "pre_height=$PRE_HEIGHT"
        echo "post_height=$POST_HEIGHT"
        echo "state_root=${COMMON_ROOT:-}"
        echo "gate=${GATE_VALUE:-unknown}"
        echo "reason=${reason}"
        echo "old_label=$OLD_LABEL"
        echo "new_label=$NEW_LABEL"
        echo "plan_name=$PLAN_NAME"
        echo "plan_height=$PLAN_HEIGHT"
        echo "log_dir=$RUN_ROOT"
    } > "$RUN_ROOT/summary.env"
}

finish() {
    local result="$1" reason="${2:-}"
    RESULT="$result"
    REASON="$reason"
    if [[ "$result" == "PASS" && "$PURGE_ON_PASS" == "1" ]]; then
        # Write the summary BEFORE removing the run dir (the file is deleted
        # with it; the stdout line is what the caller consumes).
        write_summary "$result" "$reason"
        cleanup
        rm -rf "$RUN_ROOT"
        exit 0
    fi
    if [[ -n "$RUN_ROOT" ]]; then
        log "artifacts kept at $RUN_ROOT"
    fi
    if [[ "$result" != "PASS" ]]; then
        printf '[drill] FAIL: %s\n' "$reason" >&2
    fi
    # The machine-readable line is the LAST thing on stdout, so callers can
    # simply `| tail -1` (or grep DRILL_RESULT).
    write_summary "$result" "$reason"
    if [[ "$result" == "PASS" ]]; then
        exit 0
    fi
    exit 1
}

fail() {
    local reason="$1"
    RESULT="FAIL"
    REASON="$reason"
    write_summary "FAIL" "$reason"
    printf '[drill] FAIL: %s\n' "$reason" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            [[ $# -ge 2 ]] || die "--mode needs a value (manual|onchain)"
            MODE="$2"; shift 2 ;;
        --mode=*) MODE="${1#--mode=}"; shift ;;
        --local-only) LOCAL_ONLY=1; shift ;;
        --nodes)
            [[ $# -ge 2 ]] || die "--nodes needs a value"
            NODES="$2"; shift 2 ;;
        --nodes=*) NODES="${1#--nodes=}"; shift ;;
        --binary)
            [[ $# -ge 2 ]] || die "--binary needs a path"
            OLD_BIN="$2"; shift 2 ;;
        --binary=*) OLD_BIN="${1#--binary=}"; shift ;;
        --new-binary)
            [[ $# -ge 2 ]] || die "--new-binary needs a path"
            NEW_BIN="$2"; shift 2 ;;
        --new-binary=*) NEW_BIN="${1#--new-binary=}"; shift ;;
        --plan-name)
            [[ $# -ge 2 ]] || die "--plan-name needs a value"
            PLAN_NAME="$2"; shift 2 ;;
        --plan-height)
            [[ $# -ge 2 ]] || die "--plan-height needs a value"
            PLAN_HEIGHT="$2"; shift 2 ;;
        --staged-bin)
            [[ $# -ge 2 ]] || die "--staged-bin needs a path"
            STAGED_BIN="$2"; shift 2 ;;
        --submit-cmd)
            [[ $# -ge 2 ]] || die "--submit-cmd needs a path"
            SUBMIT_CMD="$2"; shift 2 ;;
        --ready-timeout) READY_TIMEOUT="$2"; shift 2 ;;
        --resume-timeout) RESUME_TIMEOUT="$2"; shift 2 ;;
        --stop-timeout) STOP_TIMEOUT="$2"; shift 2 ;;
        --rto-budget-seconds) RTO_BUDGET_MS=$(( $2 * 1000 )); shift 2 ;;
        --min-height) MIN_HEIGHT="$2"; shift 2 ;;
        --traffic-txs) TRAFFIC_TXS="$2"; shift 2 ;;
        --onchain-timeout) ONCHAIN_TIMEOUT="$2"; shift 2 ;;
        --purge-on-pass) PURGE_ON_PASS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument '$1' (try --help)" ;;
    esac
done

[[ -n "$MODE" ]] || die "--mode is required (manual|onchain)"
[[ "$MODE" == "manual" || "$MODE" == "onchain" ]] || die "unknown mode '$MODE' (manual|onchain)"
[[ "$NODES" =~ ^[1-9][0-9]*$ ]] || die "--nodes must be a positive integer"
[[ "$LOCAL_ONLY" == "1" ]] || die "refusing to run without --local-only: this drill starts a local cluster and must never be pointed at a live one"
[[ -d /tmp/opencode ]] || die "/tmp/opencode is missing; this drill must keep every temp dir under it"

case "$RUN_ROOT" in
    "") ;;
esac
STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_ROOT="${DRILL_ROOT:-/tmp/opencode/upgrade-drill-$STAMP-$$}"
case "$RUN_ROOT" in
    /tmp/opencode/*) ;;
    *) die "RUN_ROOT must live under /tmp/opencode (got '$RUN_ROOT')" ;;
esac
mkdir -p "$RUN_ROOT/bin" "$RUN_ROOT/logs"
RUNNING_DIR="$RUN_ROOT"

# ---------------------------------------------------------------------------
# Resolve the binary under test
# ---------------------------------------------------------------------------
resolve_old_bin() {
    if [[ -n "$OLD_BIN" ]]; then
        [[ -x "$OLD_BIN" ]] || die "--binary '$OLD_BIN' is not executable"
        OLD_BIN="$(cd "$(dirname "$OLD_BIN")" && pwd)/$(basename "$OLD_BIN")"
        return
    fi
    local cand
    for cand in \
        "$ROOT/stellereum/target/debug/stellereum" \
        "$ROOT/stellereum/target/release/stellereum" \
        "$ROOT/target/debug/stellereum" \
        "$ROOT/target/release/stellereum"; do
        if [[ -x "$cand" ]]; then OLD_BIN="$cand"; return; fi
    done
    OLD_BIN="$(command -v stellereum 2>/dev/null || true)"
    [[ -n "$OLD_BIN" && -x "$OLD_BIN" ]] || die "no stellereum binary found; build it first (cargo build -p stellereum)"
}

resolve_old_bin
OLD_SHA="$(sha256_of "$OLD_BIN")"
OLD_LABEL="drill-old-${OLD_SHA:0:8}"
log "old binary: $OLD_BIN (sha256 ${OLD_SHA:0:16}…, label $OLD_LABEL)"

# Compile a tiny BLAKE3 helper: `keys init` prints the PQ transport id, while
# `validators:` / `consensus-pub` are Ed-keyed (`blake3(ed_pub)[..20]`).  The
# helper turns the Ed public key (from `wallet address`) into that id.
build_b3_helper() {
    local rlib
    B3="$RUN_ROOT/bin/b3"
    for rlib in $(find "$ROOT/stellereum/target/debug/deps" "$ROOT/stellereum/target/release/deps" \
                    -maxdepth 1 -name 'libblake3-*.rlib' 2>/dev/null); do
        cat > "$RUN_ROOT/bin/b3.rs" <<'RS'
fn main() {
    let a = std::env::args().nth(1).unwrap_or_default();
    if a.len() % 2 != 0 { std::process::exit(2); }
    let b: Vec<u8> = (0..a.len()).step_by(2)
        .map(|i| u8::from_str_radix(&a[i..i+2], 16).unwrap_or(0)).collect();
    let h = blake3::hash(&b);
    let mut s = String::new();
    for x in &h.as_bytes()[..20] { s.push_str(&format!("{x:02x}")); }
    println!("{s}");
}
RS
        if rustc --edition=2021 -O -L dependency="$(dirname "$rlib")" \
                --extern blake3="$rlib" -o "$B3" "$RUN_ROOT/bin/b3.rs" >/dev/null 2>&1; then
            return 0
        fi
    done
    die "cannot build the blake3 helper (no usable libblake3 rlib under stellereum/target); refusing to guess consensus validator ids"
}
build_b3_helper

# ---------------------------------------------------------------------------
# On-chain gate detection (must happen BEFORE any cluster is started)
# ---------------------------------------------------------------------------
detect_gate() {
    local src="$ROOT/stellereum/src/governance.rs" line raw value
    [[ -f "$src" ]] || { GATE_VALUE="unknown"; GATE_OPEN=0; return; }
    line="$(grep -E '^pub const UPGRADE_EXEC_ACTIVATION_HEIGHT: u64 = ' "$src" | head -1 || true)"
    if [[ -z "$line" ]]; then GATE_VALUE="missing"; GATE_OPEN=0; return; fi
    raw="${line#*=}"
    raw="${raw%;*}"
    raw="$(printf '%s' "$raw" | tr -d ' _')"
    GATE_VALUE="$raw"
    if [[ "$raw" == "u64::MAX" || "$raw" == "18446744073709551615" ]]; then
        GATE_OPEN=0
    elif [[ "$raw" =~ ^[0-9]+$ ]]; then
        # A finite height is only "open" from the drill's point of view if it
        # is not MAX.  The submitter still has to drive the proposal.
        GATE_OPEN=1
    else
        GATE_OPEN=0
    fi
}
detect_gate
log "UPGRADE_EXEC_ACTIVATION_HEIGHT=$GATE_VALUE (open=$GATE_OPEN)"

if [[ "$MODE" == "onchain" && "$GATE_OPEN" != "1" ]]; then
    # FAIL CLOSED: never start a cluster, never pretend the halt path ran.
    finish "FAIL" "on-chain execution is gated (UPGRADE_EXEC_ACTIVATION_HEIGHT=$GATE_VALUE); refusing to simulate a pass"
fi

if [[ "$MODE" == "onchain" ]]; then
    [[ -n "$PLAN_NAME" ]] || die "onchain mode needs --plan-name"
    [[ "$PLAN_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid --plan-name (safe single path segment, max 64 chars)"
    [[ -n "$PLAN_HEIGHT" && "$PLAN_HEIGHT" =~ ^[0-9]+$ && "$PLAN_HEIGHT" -gt 0 ]] || die "onchain mode needs a positive --plan-height"
    [[ -x "$STAGED_BIN" ]] || die "onchain mode needs an executable --staged-bin"
    [[ -x "$SUBMIT_CMD" ]] || die "onchain mode needs an executable --submit-cmd (the block-path SoftwareUpgrade submitter; see docs/UPGRADE_DRILL.md)"
    if [[ "$GATE_VALUE" =~ ^[0-9]+$ ]] && (( PLAN_HEIGHT < GATE_VALUE )); then
        die "plan height $PLAN_HEIGHT is below UPGRADE_EXEC_ACTIVATION_HEIGHT=$GATE_VALUE; a SoftwareUpgrade at that height is filtered out of the execution sweep"
    fi
    PLAN_SHA="$(sha256_of "$STAGED_BIN")"
    NEW_LABEL="$PLAN_NAME"
else
    # Manual mode: a second copy from the same tree.  Same bytes prove the
    # swap machinery and state compatibility; the label proves which image ran.
    if [[ -n "$NEW_BIN" ]]; then
        [[ -x "$NEW_BIN" ]] || die "--new-binary '$NEW_BIN' is not executable"
    else
        NEW_BIN="$RUN_ROOT/bin/stellereum-new"
        install -m 0755 "$OLD_BIN" "$NEW_BIN"
        printf 'label=%s\nsha256=%s\nsource=%s\n' \
            "drill-new-${OLD_SHA:0:8}" "$OLD_SHA" "$OLD_BIN" > "$RUN_ROOT/bin/stellereum-new.marker"
    fi
    NEW_SHA="$(sha256_of "$NEW_BIN")"
    NEW_LABEL="${DRILL_NEW_LABEL:-drill-new-${NEW_SHA:0:8}}"
    log "new binary: $NEW_BIN (sha256 ${NEW_SHA:0:16}…, label $NEW_LABEL)"
fi

# ---------------------------------------------------------------------------
# Port allocation (loopback only; never the live bases)
# ---------------------------------------------------------------------------
allocate_ports() {
    local attempt base p ok i
    for attempt in $(seq 1 80); do
        base=$(( 30000 + (RANDOM % 900) * 4 ))
        P2P_BASE="$base"
        RPC_BASE=$(( base + NODES + 2 ))
        EXP_BASE=$(( base + 2 * (NODES + 2) ))
        ok=1
        for i in $(seq 1 "$NODES"); do
            for p in "$((P2P_BASE + i))" "$((RPC_BASE + i))" "$((EXP_BASE + i))"; do
                if ! port_free "$p"; then ok=0; break 2; fi
            done
        done
        if [[ "$ok" == "1" ]]; then
            # Tripwire: never land on the documented live bases.
            for i in $(seq 1 "$NODES"); do
                p=$((RPC_BASE + i))
                if [[ "$p" -ge 18646 && "$p" -le 18649 ]]; then ok=0; fi
                p=$((P2P_BASE + i))
                if [[ "$p" -ge 19411 && "$p" -le 19414 ]]; then ok=0; fi
            done
            if [[ "$ok" == "1" ]]; then
                log "ports: p2p $((P2P_BASE + 1))..$((P2P_BASE + NODES)), rpc $((RPC_BASE + 1))..$((RPC_BASE + NODES)), explorer $((EXP_BASE + 1))..$((EXP_BASE + NODES))"
                return 0
            fi
        fi
    done
    die "could not allocate $((NODES * 3)) free loopback ports"
}
allocate_ports

# ---------------------------------------------------------------------------
# Keygen + config
# ---------------------------------------------------------------------------
keygen_all() {
    local i d out line pq fal ed cid seed_file
    for i in $(seq 1 "$NODES"); do
        d="$(node_dir "$i")"
        mkdir -p "$d/keys" "$d/data"
        out="$(STELL_KEY_PLAINTEXT=1 "$OLD_BIN" keys init --keys-dir "$d/keys" 2>&1)"
        line="$(printf '%s' "$out" | grep -oE 'NODE IDENTITY: .*' | head -1 || true)"
        [[ -n "$line" ]] || die "keys init printed no NODE IDENTITY line for node$i"
        pq="$(printf '%s' "$line" | grep -oE 'pq_pub=[^ ]+' | cut -d= -f2 || true)"
        fal="$(printf '%s' "$line" | grep -oE 'falcon=[^ ]+' | cut -d= -f2 || true)"
        [[ -n "$pq" && -n "$fal" ]] || die "could not parse keys init identity for node$i"
        seed_file="$d/keys/validator.key"
        [[ -f "$seed_file" ]] || seed_file="$d/keys/identity.key"
        [[ -f "$seed_file" ]] || die "node$i has no validator/identity key"
        ed="$("$OLD_BIN" wallet address --from-key "$(tr -d '\n\r ' < "$seed_file")" 2>/dev/null | grep -oE '^[0-9a-fA-F]{64}$' | head -1 || true)"
        [[ -n "$ed" ]] || die "could not derive the Ed25519 consensus key for node$i"
        cid="inf1:$("$B3" "$ed")"
        CID[$i]="$cid"; ED[$i]="$ed"; PQ[$i]="$pq"; FAL[$i]="$fal"
        log "node$i consensus-id=$cid ed=${ed:0:12}… pq=${pq:0:12}…"
    done
}

write_configs() {
    local i j d p2p rpc exp pqkeys
    pqkeys=""
    for i in $(seq 1 "$NODES"); do
        [[ -n "$pqkeys" ]] && pqkeys+=","
        pqkeys+="${ED[$i]}:${FAL[$i]}"
    done
    for i in $(seq 1 "$NODES"); do
        d="$(node_dir "$i")"
        p2p="$(p2p_port "$i")"; rpc=$((RPC_BASE + i)); exp=$((EXP_BASE + i))
        {
            echo "name: drill$i"
            echo "listen: \"127.0.0.1:$p2p\""
            echo "advertise: \"127.0.0.1:$p2p\""
            echo "validators:"
            for j in $(seq 1 "$NODES"); do echo "  - \"${CID[$j]}\""; done
            echo "peers:"
            for j in $(seq 1 "$NODES"); do
                [[ "$j" -eq "$i" ]] && continue
                echo "  - name: drill$j"
                echo "    consensus-pub: \"${ED[$j]}\""
                echo "    pq-pub: \"${PQ[$j]}\""
                echo "    endpoints: [\"127.0.0.1:$(p2p_port "$j")\"]"
                echo "    allow: [\"*\"]"
            done
        } > "$d/node.yaml"
        {
            echo "# generated by scripts/upgrade_drill.sh — throwaway local node $i"
            echo "STELL_KEY_PLAINTEXT=1"
            echo "STELL_NEW_CHAIN=1"
            echo "STELL_FAUCET_KEY=$FAUCET_KEY"
            echo "STELL_DEV_UNSAFE_TESTKEY=1"
            echo "STELL_LEGACY_GENESIS_ROOT=1"
            echo "STELL_PURE_PQ=1"
            echo "STELL_PEER_PQ_KEYS=$pqkeys"
            echo "STELL_ROUND_TIMEOUT_MS=10000"
            echo "STELL_BROADCAST_JOIN_MS=2000"
            echo "STELL_CATCHUP_BUDGET_MS=8000"
            echo "STELL_MIN_BLOCK_MS=250"
            echo "STELL_RPC_LISTEN=127.0.0.1:$rpc"
            echo "STELL_EXPLORER_LISTEN=127.0.0.1:$exp"
            echo "STELL_UPGRADE_HALT_MARKER=$d/data/upgrade-halt.marker"
        } > "$d/env.$i"
    done
}

audit_endpoints() {
    # Hard tripwire: every endpoint generated above MUST be loopback/private.
    local bad host
    bad="$(
        grep -rhoE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$RUN_ROOT"/node*/node.yaml 2>/dev/null \
        | sort -u | while read -r host; do
            is_private_or_loopback "$host" || echo "$host"
        done
    )"
    [[ -z "$bad" ]] || die "refusing non-loopback/private endpoints: $bad"
    log "endpoint audit: all addresses are loopback/private"
}

# ---------------------------------------------------------------------------
# Cluster lifecycle
# ---------------------------------------------------------------------------
install_live_bin() {
    # Simulate the operator's ExecStart path: one file, atomically replaced.
    mkdir -p "$RUN_ROOT/bin/live"
    LIVE_BIN="$RUN_ROOT/bin/live/stellereum"
    install -m 0755 "$OLD_BIN" "$LIVE_BIN.tmp"
    mv -f "$LIVE_BIN.tmp" "$LIVE_BIN"
    printf 'label=%s\nsha256=%s\nsource=%s\n' "$OLD_LABEL" "$OLD_SHA" "$OLD_BIN" \
        > "$RUN_ROOT/bin/live/VERSION"
}

start_node() {
    local i="$1" label="$2" d pid
    d="$(node_dir "$i")"
    (
        cd "$d"
        # Drop every inherited STELL_* so the run is exactly what env.$i says
        # (a caller's STELL_SHARDS/OBSERVER/AUTO_UPGRADE must not leak in).
        while IFS= read -r v; do unset "$v"; done < <(compgen -e | grep '^STELL_' || true)
        set -a
        # shellcheck disable=SC1091
        source "$d/env.$i"
        set +a
        export STELL_UPGRADE_VERSION="$label"
        exec "$LIVE_BIN" run --config node.yaml --shard 0
    ) >> "$d/live.log" 2>&1 &
    pid=$!
    NODE_PIDS[$i]="$pid"
    NODE_ALIVE[$i]=1
    NODE_EXIT[$i]=""
    printf '%s\n' "$pid" > "$d/node.pid"
    printf '%s\n' "$label" > "$d/version.label"
    log "node$i started (pid $pid, label $label, log $d/live.log)"
}

start_all() {
    local i label="$1"
    for i in $(seq 1 "$NODES"); do start_node "$i" "$label"; done
}

wait_alive() {
    local i pid
    for i in $(seq 1 "$NODES"); do
        pid="${NODE_PIDS[$i]:-}"
        [[ -n "$pid" ]] || return 1
        for _ in $(seq 1 100); do
            kill -0 "$pid" 2>/dev/null && break
            sleep 0.05
        done
        if ! kill -0 "$pid" 2>/dev/null; then
            warn "node$i died immediately; last log lines:" >&2
            tail -30 "$(node_dir "$i")/live.log" >&2 || true
            return 1
        fi
    done
    return 0
}

wait_cluster_ready() {
    local deadline i h epoch0 epoch ok elapsed
    deadline=$(( $(now_ms) + READY_TIMEOUT * 1000 ))
    log "waiting up to ${READY_TIMEOUT}s for all $NODES nodes to finalize..."
    while (( $(now_ms) < deadline )); do
        ok=1
        for i in $(seq 1 "$NODES"); do
            if ! grep -q 'FINALIZED block #' "$(node_dir "$i")/live.log" 2>/dev/null; then ok=0; break; fi
            h="$(rpc_height "$i")"
            if [[ -z "$h" || "$h" -lt 1 ]]; then ok=0; break; fi
        done
        if [[ "$ok" == "1" ]]; then
            epoch0="$(grep -oE 'chain epoch [0-9a-f]+' "$(node_dir 1)/live.log" | head -1 | awk '{print $3}' || true)"
            [[ -n "$epoch0" ]] || fail "node1 finalized blocks but logged no 'chain epoch' fingerprint"
            for i in $(seq 2 "$NODES"); do
                epoch="$(grep -oE 'chain epoch [0-9a-f]+' "$(node_dir "$i")/live.log" | head -1 | awk '{print $3}' || true)"
                if [[ -z "$epoch0" || "$epoch" != "$epoch0" ]]; then
                    fail "genesis epoch split at startup: node1='$epoch0' node$i='$epoch'"
                fi
            done
            log "cluster ready (epoch ${epoch0:-unknown})"
            return 0
        fi
        sleep 0.5
    done
    for i in $(seq 1 "$NODES"); do
        warn "node$i tail:" >&2
        tail -15 "$(node_dir "$i")/live.log" >&2 || true
    done
    fail "cluster did not become ready within ${READY_TIMEOUT}s"
}

wait_min_height() {
    local target="$1" timeout="$2" deadline i h min
    deadline=$(( $(now_ms) + timeout * 1000 ))
    while (( $(now_ms) < deadline )); do
        min=""
        for i in $(seq 1 "$NODES"); do
            h="$(rpc_height "$i")"
            [[ -z "$h" ]] && { min=""; break; }
            if [[ -z "$min" || "$h" -lt "$min" ]]; then min="$h"; fi
        done
        if [[ -n "$min" && "$min" -ge "$target" ]]; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

stop_all() {
    # Operator-style stop: SIGTERM to every node, then wait for the graceful
    # drain.  Returns the elapsed milliseconds in STOP_MS and validates that
    # every process exited 0 and drained (not the capped path).
    local i pid code t0
    t0="$(now_ms)"
    for i in $(seq 1 "$NODES"); do
        pid="${NODE_PIDS[$i]:-}"
        [[ -n "$pid" ]] || continue
        log "node$i SIGTERM (pid $pid)"
        kill -TERM "$pid" 2>/dev/null || true
    done
    for i in $(seq 1 "$NODES"); do
        pid="${NODE_PIDS[$i]:-}"
        [[ -n "$pid" ]] || continue
        for _ in $(seq 1 $((STOP_TIMEOUT * 10))); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            warn "node$i did not exit within ${STOP_TIMEOUT}s; SIGKILL"
            kill -KILL "$pid" 2>/dev/null || true
            set +e; wait "$pid" 2>/dev/null; code=$?; set -e
            NODE_EXIT[$i]="$code"
            NODE_ALIVE[$i]=0
            fail "node$i did not stop gracefully within ${STOP_TIMEOUT}s (exit $code)"
        fi
        set +e
        wait "$pid" 2>/dev/null
        code=$?
        set -e
        NODE_EXIT[$i]="$code"
        NODE_ALIVE[$i]=0
        if [[ "$code" -ne 0 ]]; then
            fail "node$i exited $code on SIGTERM (expected 0); see $(node_dir "$i")/live.log"
        fi
        if grep -q 'shutdown drain cap reached' "$(node_dir "$i")/live.log" 2>/dev/null; then
            fail "node$i hit the persistence drain cap on shutdown; the halt/stop RPO is not proven"
        fi
        if ! grep -q 'persistence drained; exiting' "$(node_dir "$i")/live.log" 2>/dev/null; then
            fail "node$i did not log 'persistence drained; exiting' on SIGTERM"
        fi
    done
    STOP_MS=$(( $(now_ms) - t0 ))
    NODE_PIDS=()
    log "all $NODES nodes stopped gracefully in $(ms_to_s "$STOP_MS")s"
}

capture_header() {
    # capture_header <height> -> HDR_HASH1 / HDR_ROOT1, all nodes must agree.
    #
    # Uses the DURABLE store (`stell_getBlock` + `stell_getHistoricalRoot`),
    # NOT the in-memory finalized-header window: that window starts empty on
    # restart and only records heights finalized/adopted by the new process,
    # so asking it for a pre-restart height is an honest miss.  The durable
    # root at H is the root the header at H+1 commits to (state AFTER H), with
    # its quorum certificate still retained in archive mode.
    local h="$1" i hash root
    local -a hashes=() roots=()
    for i in $(seq 1 "$NODES"); do
        hash="$(rpc_block_hash "$i" "$h")"
        root="$(rpc_historical_root "$i" $((h - 1)))"
        [[ -n "$hash" && -n "$root" ]] || fail "node$i cannot prove block/root at height $h from its durable store"
        hashes[$i]="$hash"; roots[$i]="$root"
    done
    for i in $(seq 2 "$NODES"); do
        [[ "${hashes[$i]}" == "${hashes[1]}" ]] || fail "header split at height $h: node1=${hashes[1]} node$i=${hashes[$i]}"
        [[ "${roots[$i]}" == "${roots[1]}" ]] || fail "state-root split after block $((h - 1)): node1=${roots[1]} node$i=${roots[$i]}"
    done
    HDR_HASH1="${hashes[1]}"
    HDR_ROOT1="${roots[1]}"
}

verify_running_binary() {
    local i pid expected="$1" exe cwd env_label
    for i in $(seq 1 "$NODES"); do
        pid="${NODE_PIDS[$i]:-}"
        [[ -n "$pid" ]] || fail "node$i has no pid at binary verification"
        kill -0 "$pid" 2>/dev/null || fail "node$i is not alive at binary verification"
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
        cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)"
        env_label="$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -m1 '^STELL_UPGRADE_VERSION=' | cut -d= -f2- || true)"
        [[ "$exe" == "$(readlink -f "$LIVE_BIN")" ]] || fail "node$i runs '$exe', expected '$LIVE_BIN'"
        [[ "$cwd" == "$(readlink -f "$(node_dir "$i")")" ]] || fail "node$i cwd '$cwd' is not its data dir"
        [[ "$env_label" == "$expected" ]] || fail "node$i reports STELL_UPGRADE_VERSION='$env_label', expected '$expected'"
    done
    log "verified: all nodes execute $LIVE_BIN with label '$expected'"
}

# ---------------------------------------------------------------------------
# Traffic (manual mode)
# ---------------------------------------------------------------------------
send_traffic() {
    local i count out from_addr to_addr nonce_before nonce_after bal nonce
    local -a tx_hashes=()
    from_addr="$("$OLD_BIN" wallet send-pq --falcon-seed "$FAUCET_KEY" \
        --to "$RECIPIENT_SEED" --amount 1 --rpc "$(rpc_url 1)" --dry-run 2>/dev/null \
        | grep -oE 'From:[[:space:]]+[0-9a-fA-F]{64}' | grep -oE '[0-9a-fA-F]{64}' | head -1 || true)"
    [[ -n "$from_addr" ]] || fail "could not derive the faucet PQ address for traffic"
    # The CLI can interleave tracing lines on stdout; take only the 64-hex
    # address line, never `head -1` (that once captured an ANSI log line).
    to_addr="$("$OLD_BIN" wallet address --from-key "$RECIPIENT_SEED" 2>/dev/null \
        | grep -oE '^[0-9a-fA-F]{64}$' | tail -1 || true)"
    [[ -n "$to_addr" ]] || fail "could not derive the traffic recipient address"
    read -r bal nonce_before <<< "$(rpc_balance_nonce 1 "$from_addr")"
    [[ -n "$nonce_before" ]] || fail "could not read the faucet nonce before traffic"
    log "traffic: $TRAFFIC_TXS PQ transfer(s) from ${from_addr:0:12}… nonce $nonce_before"
    for ((i = 1; i <= TRAFFIC_TXS; i++)); do
        out="$("$OLD_BIN" wallet send-pq --falcon-seed "$FAUCET_KEY" --to "$to_addr" \
            --amount 1 --rpc "$(rpc_url "$((i % NODES + 1))")" 2>&1 || true)"
        local h
        h="$(printf '%s' "$out" | grep -oE 'mempool tx hash: [0-9a-fA-F]{64}' | grep -oE '[0-9a-fA-F]{64}' | head -1 || true)"
        [[ -n "$h" ]] || h="$(printf '%s' "$out" | grep -oE 'Hash:[[:space:]]+[0-9a-fA-F]{64}' | grep -oE '[0-9a-fA-F]{64}' | head -1 || true)"
        [[ -n "$h" ]] || { printf '%s\n' "$out" >&2; fail "traffic transfer $i was not accepted by the node"; }
        tx_hashes+=("$h")
        log "traffic tx $i: ${h:0:16}…"
    done
    # Wait until the faucet nonce advanced and at least one receipt landed in a block.
    local deadline ok
    deadline=$(( $(now_ms) + 60000 ))
    while (( $(now_ms) < deadline )); do
        read -r bal nonce_after <<< "$(rpc_balance_nonce 1 "$from_addr")"
        if [[ -n "$nonce_after" && "$nonce_after" -gt "$nonce_before" ]]; then
            ok=1
            for h in "${tx_hashes[@]}"; do
                if [[ -n "$(rpc_receipt_block 1 "$h")" ]]; then ok=0; break; fi
            done
            if [[ "$ok" == "0" ]]; then
                FAUCET_ADDR="$from_addr"
                FAUCET_NONCE="$nonce_after"
                FAUCET_BALANCE="$bal"
                TRAFFIC_APPLIED=$((nonce_after - nonce_before))
                log "traffic applied: nonce $nonce_before -> $nonce_after, balance $bal"
                return 0
            fi
        fi
        sleep 0.5
    done
    fail "traffic was accepted but no transfer was finalized within 60s (no double-apply baseline)"
}

# ---------------------------------------------------------------------------
# Manual mode
# ---------------------------------------------------------------------------
run_manual() {
    local i h pre_hash pre_root pre_nonce pre_balance t0 t1 rto post_h common_hash common_root
    local post_div post_fork post_weak post_drop

    install_live_bin
    keygen_all
    write_configs
    audit_endpoints

    log "starting $NODES-node local cluster (manual drill)"
    start_all "$OLD_LABEL"
    wait_alive || fail "a node died at startup"
    wait_cluster_ready
    wait_min_height "$MIN_HEIGHT" "$READY_TIMEOUT" || fail "chain did not reach height $MIN_HEIGHT within ${READY_TIMEOUT}s"

    send_traffic

    # Let the traffic settle and pick a common finalized height to pin.
    sleep 1
    PRE_HEIGHT=""
    for i in $(seq 1 "$NODES"); do
        h="$(rpc_height "$i")"
        [[ -n "$h" ]] || fail "node$i stopped reporting a height before the baseline"
        if [[ -z "$PRE_HEIGHT" || "$h" -lt "$PRE_HEIGHT" ]]; then PRE_HEIGHT="$h"; fi
    done
    PRE_HEIGHT=$((PRE_HEIGHT - 1))
    (( PRE_HEIGHT > 0 )) || fail "baseline height is not positive"
    capture_header "$PRE_HEIGHT"
    pre_hash="$HDR_HASH1"; pre_root="$HDR_ROOT1"
    log "baseline: height $PRE_HEIGHT hash ${pre_hash:0:16}… state-root ${pre_root:0:16}…"

    read -r pre_balance pre_nonce <<< "$(rpc_balance_nonce 1 "$FAUCET_ADDR")"
    [[ -n "$pre_balance" && -n "$pre_nonce" ]] || fail "could not read the faucet account before the stop"
    [[ "$pre_nonce" == "$FAUCET_NONCE" ]] || warn "faucet nonce moved between traffic and baseline ($FAUCET_NONCE -> $pre_nonce)"

    # Integrity counters before the stop, PER NODE (a node that already
    # diverged must be compared against its own baseline, not node1's).
    wait_metrics || fail "explorer /metrics unavailable on some node before the stop"
    local -a PRE_DIV PRE_FORK PRE_WEAK PRE_DROP
    for i in $(seq 1 "$NODES"); do
        PRE_DIV[$i]="$(metric_value "$i" stell_divergence_total)"
        PRE_FORK[$i]="$(metric_value "$i" stell_fork_total)"
        PRE_WEAK[$i]="$(metric_value "$i" stell_weak_qc_refused_total)"
        PRE_DROP[$i]="$(metric_value "$i" stell_persist_queue_dropped_total)"
        [[ -n "${PRE_DIV[$i]}" && -n "${PRE_FORK[$i]}" ]] || fail "explorer /metrics unavailable on node$i before stop"
    done

    verify_running_binary "$OLD_LABEL"
    for i in $(seq 1 "$NODES"); do
        if [[ -e "$(node_dir "$i")/data/upgrade-halt.marker" ]]; then
            fail "node$i unexpectedly created an upgrade-halt marker in manual mode"
        fi
    done

    t0="$(now_ms)"
    stop_all
    log "swap: installing '$NEW_LABEL' over $LIVE_BIN"
    install -m 0755 "$NEW_BIN" "$LIVE_BIN.tmp"
    mv -f "$LIVE_BIN.tmp" "$LIVE_BIN"
    printf 'label=%s\nsha256=%s\nsource=%s\n' "$NEW_LABEL" "$NEW_SHA" "$NEW_BIN" \
        > "$RUN_ROOT/bin/live/VERSION"
    [[ "$(sha256_of "$LIVE_BIN")" == "$NEW_SHA" ]] || fail "binary swap verification failed"

    log "restarting all nodes on '$NEW_LABEL' (RTO clock is running)"
    start_all "$NEW_LABEL"
    wait_alive || fail "a node died on restart"

    # RTO = first SIGTERM -> first NEW finalized block on ANY node.
    t1=""
    while (( $(now_ms) < t0 + RESUME_TIMEOUT * 1000 )); do
        for i in $(seq 1 "$NODES"); do
            h="$(rpc_height "$i")"
            if [[ -n "$h" && "$h" -gt "$PRE_HEIGHT" ]]; then
                t1="$(now_ms)"
                RTO_MS=$((t1 - t0))
                break 2
            fi
        done
        sleep 0.1
    done
    [[ -n "$t1" ]] || fail "no node finalized a block above $PRE_HEIGHT within ${RESUME_TIMEOUT}s of the stop"
    log "first new finalized block after $(ms_to_s "$RTO_MS")s"
    (( RTO_MS <= RTO_BUDGET_MS )) || fail "RTO $(ms_to_s "$RTO_MS")s exceeds budget $(ms_to_s "$RTO_BUDGET_MS")s"

    # All nodes must resume (not just the first one).
    wait_min_height $((PRE_HEIGHT + 1)) "$RESUME_TIMEOUT" \
        || fail "not all nodes resumed above height $PRE_HEIGHT within ${RESUME_TIMEOUT}s"

    verify_running_binary "$NEW_LABEL"

    # Historical block at PRE_HEIGHT must be byte-identical (no reorg / no
    # double-apply).  Both the hash and the QC-anchored historical root are
    # served from the durable store, so a pre-restart height is answerable.
    capture_header "$PRE_HEIGHT"
    [[ "$HDR_HASH1" == "$pre_hash" ]] || fail "block $PRE_HEIGHT changed hash after restart (${pre_hash:0:16}… -> ${HDR_HASH1:0:16}…): a reorg or double-apply"
    [[ "$HDR_ROOT1" == "$pre_root" ]] || fail "state root after block $((PRE_HEIGHT - 1)) changed after restart (${pre_root:0:16}… -> ${HDR_ROOT1:0:16}…): a reorg or double-apply"
    log "historical block $PRE_HEIGHT and its QC-anchored state root are unchanged"

    # No new traffic after restart: the faucet nonce/balance must be unchanged.
    local post_balance post_nonce
    read -r post_balance post_nonce <<< "$(rpc_balance_nonce 1 "$FAUCET_ADDR")"
    [[ "$post_nonce" == "$pre_nonce" ]] || fail "faucet nonce changed across restart ($pre_nonce -> $post_nonce): a finalized transfer was re-applied"
    [[ "$post_balance" == "$pre_balance" ]] || fail "faucet balance changed across restart ($pre_balance -> $post_balance): a finalized transfer was re-applied"

    # Common post-restart height: all nodes must agree on the header there.
    POST_HEIGHT=""
    for i in $(seq 1 "$NODES"); do
        h="$(rpc_height "$i")"
        [[ -n "$h" ]] || fail "node$i stopped reporting a height after resume"
        if [[ -z "$POST_HEIGHT" || "$h" -lt "$POST_HEIGHT" ]]; then POST_HEIGHT="$h"; fi
    done
    (( POST_HEIGHT > PRE_HEIGHT )) || fail "common post-restart height $POST_HEIGHT did not advance past $PRE_HEIGHT"
    capture_header "$POST_HEIGHT"
    common_hash="$HDR_HASH1"; common_root="$HDR_ROOT1"
    COMMON_ROOT="$common_root"
    log "resumed: common height $POST_HEIGHT hash ${common_hash:0:16}… state-root ${common_root:0:16}…"

    # Integrity counters after: no divergence/fork/weak-QC/dropped-persist growth.
    wait_metrics || fail "explorer /metrics unavailable on some node after restart"
    for i in $(seq 1 "$NODES"); do
        post_div="$(metric_value "$i" stell_divergence_total)"
        post_fork="$(metric_value "$i" stell_fork_total)"
        post_weak="$(metric_value "$i" stell_weak_qc_refused_total)"
        post_drop="$(metric_value "$i" stell_persist_queue_dropped_total)"
        [[ -n "$post_div" && -n "$post_fork" ]] || fail "explorer /metrics unavailable on node$i after restart"
        (( post_div == PRE_DIV[$i] )) || fail "node$i stell_divergence_total grew (${PRE_DIV[$i]} -> $post_div)"
        (( post_fork == PRE_FORK[$i] )) || fail "node$i stell_fork_total grew (${PRE_FORK[$i]} -> $post_fork)"
        (( post_weak == PRE_WEAK[$i] )) || fail "node$i stell_weak_qc_refused_total grew (${PRE_WEAK[$i]} -> $post_weak)"
        (( post_drop == PRE_DROP[$i] )) || fail "node$i stell_persist_queue_dropped_total grew (${PRE_DROP[$i]} -> $post_drop)"
    done

    # Final state root cross-check at the live head (best-effort: heads may differ
    # by a block while the chain is live, so the authoritative check is the
    # common-height header above).
    log "PASS manual: $NODES nodes, RTO $(ms_to_s "$RTO_MS")s, heights $PRE_HEIGHT -> $POST_HEIGHT, state-root ${COMMON_ROOT:0:16}…"
    finish "PASS" ""
}

# ---------------------------------------------------------------------------
# On-chain mode (only reachable when the gate is open)
# ---------------------------------------------------------------------------
run_onchain() {
    local i h deadline pid code halted_at marker
    local pre_plan_height pre_hash pre_root
    local halt_seen=0 halt_t0="" rto_base
    local -a halt_pids=()

    [[ -n "$PLAN_SHA" ]] || PLAN_SHA="$(sha256_of "$STAGED_BIN")"
    install_live_bin
    keygen_all
    write_configs
    audit_endpoints

    log "starting $NODES-node local cluster (on-chain drill, gate=$GATE_VALUE)"
    start_all "$OLD_LABEL"
    wait_alive || fail "a node died at startup"
    wait_cluster_ready
    wait_min_height "$MIN_HEIGHT" "$READY_TIMEOUT" || fail "chain did not reach height $MIN_HEIGHT"

    h="$(rpc_height 1)"
    (( PLAN_HEIGHT > h + 10 )) || fail "plan height $PLAN_HEIGHT must be at least 10 blocks above the current height $h"

    # Baseline the CURRENT finalized head (the plan height is in the future;
    # we cannot query a header that has not been produced yet).
    pre_plan_height="$(rpc_height 1)"
    [[ -n "$pre_plan_height" && "$pre_plan_height" -gt 0 ]] || fail "no finalized height to baseline before the on-chain drill"
    capture_header "$pre_plan_height"
    pre_hash="$HDR_HASH1"; pre_root="$HDR_ROOT1"
    log "pre-halt baseline: height $pre_plan_height hash ${pre_hash:0:16}…"

    log "invoking block-path submitter: $SUBMIT_CMD"
    DRILL_RPC_URLS="$(for i in $(seq 1 "$NODES"); do printf '%s,' "$(rpc_url "$i")"; done)"
    export DRILL_RPC_URLS="${DRILL_RPC_URLS%,}"
    export DRILL_PLAN_NAME="$PLAN_NAME" DRILL_PLAN_HEIGHT="$PLAN_HEIGHT" \
           DRILL_PLAN_SHA256="$PLAN_SHA" DRILL_STAGED_BIN="$STAGED_BIN" \
           DRILL_RUN_ROOT="$RUN_ROOT"
    if ! timeout "$ONCHAIN_TIMEOUT" "$SUBMIT_CMD"; then
        fail "block-path submitter failed or timed out; no SoftwareUpgrade was driven to execution"
    fi

    # Wait until the committed plan is visible and the chain reaches the halt.
    deadline=$(( $(now_ms) + ONCHAIN_TIMEOUT * 1000 ))
    log "waiting up to ${ONCHAIN_TIMEOUT}s for the plan to execute and the nodes to halt..."
    while (( $(now_ms) < deadline )); do
        local all_halted=1
        for i in $(seq 1 "$NODES"); do
            pid="${NODE_PIDS[$i]:-}"
            if kill -0 "$pid" 2>/dev/null; then
                all_halted=0
                continue
            fi
            if [[ -z "${NODE_EXIT[$i]:-}" ]]; then
                set +e; wait "$pid" 2>/dev/null; code=$?; set -e
                NODE_EXIT[$i]="$code"; NODE_ALIVE[$i]=0
                [[ -z "$halt_t0" ]] && halt_t0="$(now_ms)"
            fi
        done
        if [[ "$all_halted" == "1" ]]; then halt_seen=1; break; fi
        sleep 0.25
    done
    [[ "$halt_seen" == "1" ]] || fail "nodes did not halt within ${ONCHAIN_TIMEOUT}s (plan never executed?)"

    halted_at=0
    for i in $(seq 1 "$NODES"); do
        code="${NODE_EXIT[$i]:-}"
        [[ "$code" == "42" ]] || fail "node$i exited '$code' instead of 42; the upgrade halt did not fire"
        marker="$(node_dir "$i")/data/upgrade-halt.marker"
        [[ -f "$marker" ]] || fail "node$i exited 42 but wrote no halt marker at $marker"
        grep -q '^stell-upgrade-halt v1$' "$marker" || fail "node$i marker has a bad header"
        grep -q "^plan_name=$PLAN_NAME$" "$marker" || fail "node$i marker plan_name mismatch"
        grep -q "^height=$PLAN_HEIGHT$" "$marker" || fail "node$i marker height mismatch (expected $PLAN_HEIGHT)"
        grep -q "^plan_sha256=$PLAN_SHA$" "$marker" || fail "node$i marker plan_sha256 mismatch"
        grep -q '^target_version=' "$marker" || fail "node$i marker has no target_version"
        local node_halted
        node_halted="$(grep -E '^halted_at_height=' "$marker" | cut -d= -f2 || true)"
        [[ -n "$node_halted" && "$node_halted" -ge "$PLAN_HEIGHT" ]] || fail "node$i halted_at_height=$node_halted is before the plan height $PLAN_HEIGHT"
        (( node_halted > halted_at )) && halted_at="$node_halted"
        grep -q 'halt marker written' "$(node_dir "$i")/live.log" || fail "node$i log has no 'halt marker written' line"
        grep -q 'persistence drained' "$(node_dir "$i")/live.log" || fail "node$i log has no 'persistence drained' line"
        if grep -q 'halt drain CAP reached' "$(node_dir "$i")/live.log"; then
            fail "node$i hit the halt drain cap; the halt RPO is not proven"
        fi
    done
    log "all $NODES nodes exited 42 with a verified marker and a completed drain"

    # FAIL-CLOSED GUARD: the OLD binary must refuse to start on this marker.
    log "guard check: restarting the OLD binary against the marker (it MUST refuse)"
    for i in $(seq 1 "$NODES"); do
        (
            cd "$(node_dir "$i")"
            while IFS= read -r v; do unset "$v"; done < <(compgen -e | grep '^STELL_' || true)
            set -a; source "$(node_dir "$i")/env.$i"; set +a
            export STELL_UPGRADE_VERSION="$OLD_LABEL"
            exec "$LIVE_BIN" run --config node.yaml --shard 0
        ) >> "$(node_dir "$i")/live.log" 2>&1 &
        halt_pids[$i]=$!
        NODE_PIDS[$i]=$!   # so the trap cleans up an interrupted guard check too
    done
    for i in $(seq 1 "$NODES"); do
        pid="${halt_pids[$i]}"
        for _ in $(seq 1 300); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
        if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
        set +e; wait "$pid" 2>/dev/null; code=$?; set -e
        [[ "$code" -ne 0 ]] || fail "node$i OLD binary started successfully despite the halt marker (guard failed open)"
        grep -q 'REFUSING TO START CONSENSUS' "$(node_dir "$i")/live.log" \
            || fail "node$i OLD binary exited $code but did not print the guard refusal"
    done
    log "guard check passed: the OLD binary refuses the marker"

    # Install the staged binary (the plan-named one), then restart.
    rto_base="${halt_t0:-$(now_ms)}"
    log "installing staged binary ($PLAN_NAME, sha256 ${PLAN_SHA:0:16}…)"
    install -m 0755 "$STAGED_BIN" "$LIVE_BIN.tmp"
    mv -f "$LIVE_BIN.tmp" "$LIVE_BIN"
    printf 'label=%s\nsha256=%s\nsource=%s\n' "$PLAN_NAME" "$PLAN_SHA" "$STAGED_BIN" \
        > "$RUN_ROOT/bin/live/VERSION"
    [[ "$(sha256_of "$LIVE_BIN")" == "$PLAN_SHA" ]] || fail "staged binary swap verification failed"

    start_all "$PLAN_NAME"
    wait_alive || fail "a node died after installing the staged binary"

    deadline=$(( $(now_ms) + RESUME_TIMEOUT * 1000 ))
    RTO_MS=0
    while (( $(now_ms) < deadline )); do
        for i in $(seq 1 "$NODES"); do
            h="$(rpc_height "$i")"
            if [[ -n "$h" && "$h" -gt "$halted_at" ]]; then
                RTO_MS=$(( $(now_ms) - rto_base ))
                break 2
            fi
        done
        sleep 0.1
    done
    (( RTO_MS > 0 )) || fail "chain did not resume above halt height $halted_at within ${RESUME_TIMEOUT}s"
    log "chain resumed $(ms_to_s "$RTO_MS")s after the halt"

    wait_min_height $((halted_at + 1)) "$RESUME_TIMEOUT" || fail "not all nodes resumed above $halted_at"
    verify_running_binary "$PLAN_NAME"

    for i in $(seq 1 "$NODES"); do
        [[ ! -e "$(node_dir "$i")/data/upgrade-halt.marker" ]] \
            || fail "node$i marker was not cleared by the upgraded binary's startup guard"
        grep -q 'cleared the upgrade-halt marker' "$(node_dir "$i")/live.log" \
            || fail "node$i log does not show the marker being cleared"
    done

    # Historical chain before the halt must be unchanged.
    capture_header "$pre_plan_height"
    [[ "$HDR_HASH1" == "$pre_hash" ]] || fail "block $pre_plan_height changed after the upgrade"
    [[ "$HDR_ROOT1" == "$pre_root" ]] || fail "pre-halt state root after block $((pre_plan_height - 1)) changed after the upgrade"

    POST_HEIGHT=""
    for i in $(seq 1 "$NODES"); do
        h="$(rpc_height "$i")"
        [[ -n "$h" ]] || fail "node$i stopped reporting a height after the upgrade"
        if [[ -z "$POST_HEIGHT" || "$h" -lt "$POST_HEIGHT" ]]; then POST_HEIGHT="$h"; fi
    done
    (( POST_HEIGHT > halted_at )) || fail "common height $POST_HEIGHT did not advance past halt height $halted_at"
    capture_header "$POST_HEIGHT"
    COMMON_ROOT="$HDR_ROOT1"

    log "PASS onchain: plan '$PLAN_NAME' at $PLAN_HEIGHT, halt $halted_at, RTO $(ms_to_s "$RTO_MS")s, state-root ${COMMON_ROOT:0:16}…"
    finish "PASS" ""
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

log "mode=$MODE nodes=$NODES gate=$GATE_VALUE run=$RUN_ROOT"
case "$MODE" in
    manual)  run_manual ;;
    onchain) run_onchain ;;
    *)       die "unknown mode '$MODE'" ;;
esac
