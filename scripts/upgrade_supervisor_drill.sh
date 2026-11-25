#!/usr/bin/env bash
# ==============================================================================
# upgrade_supervisor_drill.sh — throwaway-cluster rehearsal of the
# `stellereum-upgrader` supervisor workflow:
#
#   halt -> durable marker -> verify staged bytes -> atomic swap -> restart
#        -> supermajority restart gate -> resume
#
# It NEVER touches a live cluster: one solo validator is started on loopback
# ports and every directory lives under /tmp/opencode. The halt is synthesized
# from the real marker format after a graceful SIGTERM (the on-chain drill in
# scripts/upgrade_drill.sh covers the governance-triggered exit 42 when its
# gate is open). Every supervisor refusal is exercised before the real apply.
#
# Exit: 0 = PASS, 1 = FAIL. The last stdout line is machine-readable.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SUPERVISOR="${SUPERVISOR_BIN:-}"
NODE_BIN="${STELL_BIN:-}"
STAGED_IN=""
PLAN_NAME="drill-v2"
KEEP=1
RUN_ROOT=""

log()  { printf '[sup-drill] %s\n' "$*"; }
warn() { printf '[sup-drill] WARN: %s\n' "$*" >&2; }
die()  { printf '[sup-drill] FATAL: %s\n' "$*" >&2; exit 2; }
now_ms() { date +%s%3N; }
sha256_of() { sha256sum "$1" | awk '{print $1}'; }

usage() {
    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --supervisor) SUPERVISOR="$2"; shift 2 ;;
        --supervisor=*) SUPERVISOR="${1#--supervisor=}"; shift ;;
        --binary) NODE_BIN="$2"; shift 2 ;;
        --binary=*) NODE_BIN="${1#--binary=}"; shift ;;
        --new-binary) STAGED_IN="$2"; shift 2 ;;
        --new-binary=*) STAGED_IN="${1#--new-binary=}"; shift ;;
        --plan-name) PLAN_NAME="$2"; shift 2 ;;
        --plan-name=*) PLAN_NAME="${1#--plan-name=}"; shift ;;
        --keep) KEEP=1; shift ;;
        --purge-on-pass) KEEP=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument '$1' (try --help)" ;;
    esac
done

[[ -d /tmp/opencode ]] || die "/tmp/opencode is missing; this drill keeps every temp dir under it"
[[ "$PLAN_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "invalid --plan-name"

find_bin() {
    local env_name="$1" name="$2" cand
    local explicit="${!env_name:-}"
    if [[ -n "$explicit" ]]; then
        [[ -x "$explicit" ]] || die "$name '$explicit' is not executable"
        printf '%s' "$(cd "$(dirname "$explicit")" && pwd)/$(basename "$explicit")"
        return
    fi
    for cand in \
        "$ROOT/target/release/$name" \
        "$ROOT/target/debug/$name" \
        "$ROOT/stellereum/target/release/$name" \
        "$ROOT/stellereum/target/debug/$name"; do
        if [[ -x "$cand" ]]; then printf '%s' "$cand"; return; fi
    done
    command -v "$name" 2>/dev/null || true
}

if [[ -z "$SUPERVISOR" ]]; then
    SUPERVISOR="$(find_bin SUPERVISOR_BIN stellereum-upgrader)"
fi
[[ -n "$SUPERVISOR" && -x "$SUPERVISOR" ]] || die "no stellereum-upgrader binary; build it with: cargo build -p stellereum-upgrader"
if [[ -z "$NODE_BIN" ]]; then
    NODE_BIN="$(find_bin STELL_BIN stellereum)"
fi
[[ -n "$NODE_BIN" && -x "$NODE_BIN" ]] || die "no stellereum node binary; build it with: cargo build -p stellereum"

STAMP="$(date +%Y%m%d-%H%M%S)"
RUN_ROOT="${DRILL_ROOT:-/tmp/opencode/supervisor-drill-$STAMP-$$}"
case "$RUN_ROOT" in
    /tmp/opencode/*) ;;
    *) die "RUN_ROOT must live under /tmp/opencode (got '$RUN_ROOT')" ;;
esac
NODE_DIR="$RUN_ROOT/node"
LIVE_BIN="$RUN_ROOT/bin/live/stellereum"
MARKER="$NODE_DIR/data/upgrade-halt.marker"
PROGRESS="$RUN_ROOT/progress.log"
mkdir -p "$RUN_ROOT/bin/live" "$NODE_DIR/data" "$NODE_DIR/keys"

NODE_PID=""

cleanup() {
    if [[ -n "$NODE_PID" ]] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill -TERM "$NODE_PID" 2>/dev/null || true
        for _ in $(seq 1 100); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 0.1; done
        kill -KILL "$NODE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

port_free() {
    python3 - "$1" <<'PY' >/dev/null 2>&1
import socket, sys
port = int(sys.argv[1])
for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
    s = socket.socket(socket.AF_INET, kind)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        sys.exit(1)
    finally:
        s.close()
PY
}

P2P=""; RPC=""; EXP=""
for _ in $(seq 1 80); do
    base=$(( 38000 + (RANDOM % 500) * 3 ))
    if port_free "$base" && port_free $((base + 1)) && port_free $((base + 2)); then
        P2P="$base"; RPC=$((base + 1)); EXP=$((base + 2)); break
    fi
done
[[ -n "$P2P" ]] || die "could not allocate loopback ports"
log "ports: p2p $P2P rpc $RPC explorer $EXP"

cat > "$NODE_DIR/node.yaml" <<EOF
name: supdrill
listen: "127.0.0.1:$P2P"
advertise: "127.0.0.1:$P2P"
validators: []
peers: []
EOF

FAUCET_KEY="1111111111111111111111111111111111111111111111111111111111111111"
cat > "$RUN_ROOT/env.sh" <<EOF
export STELL_KEY_PLAINTEXT=1
export STELL_NEW_CHAIN=1
export STELL_FAUCET_KEY=$FAUCET_KEY
export STELL_DEV_UNSAFE_TESTKEY=1
export STELL_LEGACY_GENESIS_ROOT=1
export STELL_PURE_PQ=1
export STELL_MIN_BLOCK_MS=100
export STELL_SNAPSHOT_INTERVAL=50
export STELL_RPC_LISTEN=127.0.0.1:$RPC
export STELL_EXPLORER_LISTEN=127.0.0.1:$EXP
export STELL_UPGRADE_HALT_MARKER=$MARKER
EOF

rpc_height() {
    local out hex
    out="$(curl -s -m 3 -X POST -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}' \
        "http://127.0.0.1:$RPC" 2>/dev/null || true)"
    hex="$(printf '%s' "$out" | grep -oE '"result":"0x[0-9a-fA-F]+"' | head -1 | cut -d'"' -f4 || true)"
    if [[ -z "$hex" ]]; then echo ""; return 0; fi
    printf '%d' "$((16#${hex#0x}))"
}

wait_height() {
    local target="$1" timeout="$2" deadline h
    deadline=$(( $(now_ms) + timeout * 1000 ))
    while (( $(now_ms) < deadline )); do
        h="$(rpc_height)"
        if [[ -n "$h" && "$h" -ge "$target" ]]; then return 0; fi
        sleep 0.2
    done
    return 1
}

start_node() {
    local label="$1" gate="$2"
    (
        cd "$NODE_DIR"
        # Do not let a caller's STELL_* leak into the drill.
        while IFS= read -r v; do unset "$v"; done < <(compgen -e | grep '^STELL_' || true)
        # shellcheck disable=SC1091
        . "$RUN_ROOT/env.sh"
        export STELL_UPGRADE_VERSION="$label"
        [[ -n "$gate" ]] && export STELL_WAIT_SUPERMAJORITY="$gate"
        exec "$LIVE_BIN" run --config node.yaml --shard 0
    ) >> "$NODE_DIR/live.log" 2>&1 &
    NODE_PID=$!
    printf '%s\n' "$NODE_PID" > "$NODE_DIR/node.pid"
    log "node started (pid $NODE_PID, version label '$label', gate '${gate:-off}')"
}

stop_node() {
    [[ -n "$NODE_PID" ]] || return 0
    log "SIGTERM node $NODE_PID (graceful halt phase)"
    kill -TERM "$NODE_PID" 2>/dev/null || true
    for _ in $(seq 1 600); do
        kill -0 "$NODE_PID" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$NODE_PID" 2>/dev/null; then
        kill -KILL "$NODE_PID" 2>/dev/null || true
        die "node did not stop gracefully within 60s"
    fi
    wait "$NODE_PID" 2>/dev/null || true
    NODE_PID=""
}

install -m 0755 "$NODE_BIN" "$LIVE_BIN.tmp"
mv -f "$LIVE_BIN.tmp" "$LIVE_BIN"
OLD_SHA="$(sha256_of "$LIVE_BIN")"
log "old node binary: $NODE_BIN (sha256 ${OLD_SHA:0:16}…)"

start_node "drill-old" ""
wait_height 50 120 || { tail -40 "$NODE_DIR/live.log" >&2 || true; die "cluster did not reach the snapshot height 50"; }
HALT="$(rpc_height)"
[[ -n "$HALT" && "$HALT" -ge 50 ]] || die "no finalized height at/above the snapshot height before halt"
PLAN_HEIGHT=50
log "cluster reached height $HALT (committed snapshot at $PLAN_HEIGHT)"

stop_node
grep -q 'persistence drained; exiting' "$NODE_DIR/live.log" \
    || die "graceful halt did not log a completed persistence drain"

if [[ -n "$STAGED_IN" ]]; then
    [[ -x "$STAGED_IN" ]] || die "--new-binary '$STAGED_IN' is not executable"
    install -m 0755 "$STAGED_IN" "$RUN_ROOT/bin/stellereum-staged"
else
    install -m 0755 "$NODE_BIN" "$RUN_ROOT/bin/stellereum-staged"
fi
STAGED="$RUN_ROOT/bin/stellereum-staged"
STAGED_SHA="$(sha256_of "$STAGED")"

# 1. The durable marker the halted node writes, exactly as the node renders it.
cat > "$MARKER" <<EOF
stell-upgrade-halt v1
height=$PLAN_HEIGHT
halted_at_height=$HALT
plan_name=$PLAN_NAME
plan_sha256=$STAGED_SHA
target_version=$PLAN_NAME
running_version=drill-old
halted_unix=$(date +%s)
EOF
log "halt marker written: plan_height=$PLAN_HEIGHT halted_at=$HALT plan=$PLAN_NAME sha256=${STAGED_SHA:0:16}…"
grep -q '^stell-upgrade-halt v1$' "$MARKER" || die "marker header is wrong"

supervisor() {
    "$SUPERVISOR" --marker "$MARKER" --staged "$STAGED" --progress "$PROGRESS" "$@"
}

# 2. Dry-run must verify but change nothing.
LIVE_SHA_BEFORE="$(sha256_of "$LIVE_BIN")"
supervisor --no-wait > "$RUN_ROOT/dry-run.log" 2>&1 \
    || { cat "$RUN_ROOT/dry-run.log" >&2; die "supervisor dry-run failed"; }
[[ "$(sha256_of "$LIVE_BIN")" == "$LIVE_SHA_BEFORE" ]] \
    || die "dry-run modified the live binary"
grep -q 'DRY RUN' "$RUN_ROOT/dry-run.log" || die "dry-run did not declare itself"
log "dry-run: verified and left the live binary untouched"

# 3. Refusals must be non-zero and must not touch the live binary.
printf 'not the planned bytes\n' > "$RUN_ROOT/bin/wrong-bytes"
chmod 755 "$RUN_ROOT/bin/wrong-bytes"
if supervisor --no-wait --staged "$RUN_ROOT/bin/wrong-bytes" > "$RUN_ROOT/mismatch.log" 2>&1; then
    die "supervisor accepted a digest mismatch"
fi
grep -q 'sha256 mismatch' "$RUN_ROOT/mismatch.log" || die "digest refusal did not name the mismatch"
[[ "$(sha256_of "$LIVE_BIN")" == "$LIVE_SHA_BEFORE" ]] \
    || die "refused digest mismatch still touched the live binary"
ln -s "$STAGED" "$RUN_ROOT/bin/staged-link"
if supervisor --no-wait --staged "$RUN_ROOT/bin/staged-link" > "$RUN_ROOT/symlink.log" 2>&1; then
    die "supervisor accepted a symlinked staged binary"
fi
grep -q 'SYMLINK' "$RUN_ROOT/symlink.log" || die "symlink refusal was not named"
chmod 757 "$STAGED"
if supervisor --no-wait > "$RUN_ROOT/world.log" 2>&1; then
    die "supervisor accepted a world-writable staged binary"
fi
grep -q 'WORLD-WRITABLE' "$RUN_ROOT/world.log" || die "world-writable refusal was not named"
chmod 755 "$STAGED"
log "refusals: digest mismatch, symlink and world-writable are all non-zero"

# 4. Apply: the supervisor owns the atomic rename and the restart command.
cat > "$RUN_ROOT/restart.sh" <<EOF
#!/bin/sh
set -e
cd "$NODE_DIR"
. "$RUN_ROOT/env.sh"
export STELL_UPGRADE_VERSION="$PLAN_NAME"
export STELL_WAIT_SUPERMAJORITY="$PLAN_HEIGHT"
nohup "$LIVE_BIN" run --config node.yaml --shard 0 >> "$NODE_DIR/live.log" 2>&1 &
echo \$! > "$NODE_DIR/node.pid"
EOF
chmod 755 "$RUN_ROOT/restart.sh"

log "applying supervisor swap (live=$LIVE_BIN)"
if ! supervisor --apply --no-wait --live "$LIVE_BIN" \
        --restart-cmd "sh $RUN_ROOT/restart.sh" > "$RUN_ROOT/apply.log" 2>&1; then
    cat "$RUN_ROOT/apply.log" >&2
    die "supervisor apply failed"
fi
[[ "$(sha256_of "$LIVE_BIN")" == "$STAGED_SHA" ]] || die "live binary does not match the staged digest"
NODE_PID="$(cat "$NODE_DIR/node.pid" 2>/dev/null || true)"
[[ -n "$NODE_PID" ]] || die "restart command did not record a node pid"
log "supervisor installed the verified bytes and the service restarted"

deadline=$(( $(now_ms) + 90000 ))
RESUMED=""
while (( $(now_ms) < deadline )); do
    h="$(rpc_height)"
    if [[ -n "$h" && "$h" -gt "$HALT" ]]; then RESUMED="$h"; break; fi
    sleep 0.2
done
[[ -n "$RESUMED" ]] || { tail -60 "$NODE_DIR/live.log" >&2 || true; die "chain did not resume above halt height $HALT"; }
[[ ! -e "$MARKER" ]] || die "upgraded node did not clear the halt marker"
grep -q 'cleared the upgrade-halt marker' "$NODE_DIR/live.log" \
    || die "node log does not show the marker being cleared"
grep -q '\[upgrade-gate\]' "$NODE_DIR/live.log" \
    || die "node did not run the supermajority restart gate"
grep -q 'supermajority verified' "$NODE_DIR/live.log" \
    || die "supermajority gate did not verify the (solo) committed set"
grep -q 'step=install' "$PROGRESS" || die "progress journal has no install step"
grep -q 'step=restart' "$PROGRESS" || die "progress journal has no restart step"
grep -q 'step=done' "$PROGRESS" || die "progress journal has no done step"

log "PASS: halt $HALT -> marker -> supervisor swap -> resume at $RESUMED"
if [[ "$KEEP" == "0" ]]; then
    rm -rf "$RUN_ROOT"
else
    log "artifacts kept at $RUN_ROOT"
fi
printf 'SUP_DRILL_RESULT=PASS halt=%s resumed=%s plan=%s sha256=%s log_dir=%s\n' \
    "$HALT" "$RESUMED" "$PLAN_NAME" "$STAGED_SHA" "$RUN_ROOT"
exit 0
