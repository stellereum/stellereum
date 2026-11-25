#!/usr/bin/env bash
# =============================================================================
# soak_two_shard.sh — live soak for the fixed public two-shard configuration.
#
# Starts real 2-shard processes (`STELL_SHARDS=0,1`, masterchain + workchain 1)
# and soaks them for a configurable wall-clock duration (default 30 minutes).
# Every check runs against a REAL node over JSON-RPC / its log; there is no
# in-process shortcut. Each role is a solo single-validator process
# (`validators: []`), so the roles derive the SAME genesis and can be compared;
# a production multi-validator cluster uses the same two-shard process shape.
#
# The run has TWO sequential phases so a busy host never starves the
# in-process shard-1 task of one of three concurrent full nodes:
#   phase 1 — `alpha` + `beta`: the independent determinism pair;
#   phase 2 — `xpc` alone: the cross-shard exactly-once probe.
#
# What it proves, every interval:
#   1. HEIGHTS: both shards' finalized tips advance on every cluster. A shard
#      that stops advancing (or regresses) fails the soak immediately.
#   2. ROOTS: two INDEPENDENTLY BUILT clusters (`alpha`, `beta`) start from the
#      same deterministic genesis, receive the SAME signed same-shard transfer
#      bytes, and must serve the SAME shard-0 state root at the same height
#      (`stell_getHistoricalRoot`). Their shard-1 roots must also agree. A
#      root mismatch is a hard failure (non-zero exit).
#      The cross-shard cluster is separate on purpose: a 2PC record commits its
#      prepared/decided HEIGHTS into the state digest, so two live clusters
#      that include the same cross-shard transfer at different heights are
#      EXPECTED to differ. Determinism is therefore measured on height-neutral
#      same-shard traffic, where the state is a pure function of the inputs.
#   3. 2PC EXACTLY-ONCE: the second phase boots `xpc` alone and sends a real
#      cross-shard PQ transfer (source shard 0 -> target shard 1). By default
#      the same raw bytes are also re-submitted `SOAK_REPLAYS` times (default
#      0; set it >0 for an adversarial idempotency run), and the soak asserts:
#        * the source is debited exactly `amount + fee_charged` (receipt), once;
#        * the sender nonce advances by exactly one per transfer;
#        * the target's committed log credits exactly ONE message per transfer
#          (`cross-shard inbound credited N message(s) on shard 1`), never more.
#
# Exit status: 0 only when every check passed for the whole duration; 1 on the
# first divergence (stall, root mismatch, duplicate credit, wrong debit, boot
# failure). On failure the relevant log tails are printed.
#
# Usage:
#   scripts/soak_two_shard.sh                        # 30 min, own funded key
#   scripts/soak_two_shard.sh --duration 600         # 10 min
#   scripts/soak_two_shard.sh --dev                  # public DEV key (local only)
#   SOAK_DURATION_SECS=120 scripts/soak_two_shard.sh --dev
#
# Required for a real (non-dev) run: STELL_FAUCET_KEY (or STELL_FAUCET_KEY_FILE)
# naming the genesis-funded faucet seed, exactly as the node uses it.
#
# Tunables (env or flags):
#   SOAK_DURATION_SECS   total soak seconds             (default 1800)
#   SOAK_INTERVAL_SECS   seconds between checkpoints    (default 60)
#   SOAK_AMOUNT_NANO     cross-shard amount per tick    (default 1000000)
#   SOAK_REPLAYS         duplicate raw submissions      (default 0)
#   SOAK_BASE_DIR        run directory                  (default run/soak_two_shard)
#   SOAK_P2P_BASE / SOAK_RPC_BASE / SOAK_EXPLORER_BASE  port bases
#   SOAK_READY_TIMEOUT   seconds to wait for both shards (default 180)
#   SOAK_TX_TIMEOUT      seconds to wait for one tx/credit (default 120)
#   SOAK_KEEP=1          keep the run directory and processes on exit
#
# The binary is never built here. Set STELL_BIN, or let the script find the
# usual debug/release paths / PATH.
# =============================================================================
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DURATION="${SOAK_DURATION_SECS:-1800}"
INTERVAL="${SOAK_INTERVAL_SECS:-60}"
AMOUNT="${SOAK_AMOUNT_NANO:-1000000}"
REPLAYS="${SOAK_REPLAYS:-0}"
BASE="${SOAK_BASE_DIR:-$ROOT/run/soak_two_shard}"
P2P_BASE="${SOAK_P2P_BASE:-19610}"
RPC_BASE="${SOAK_RPC_BASE:-19645}"
EXP_BASE="${SOAK_EXPLORER_BASE:-19680}"
READY_TIMEOUT="${SOAK_READY_TIMEOUT:-180}"
TX_TIMEOUT="${SOAK_TX_TIMEOUT:-120}"
KEEP="${SOAK_KEEP:-0}"
DEV=0
BIN="${STELL_BIN:-}"

# Public dev seed used by scripts/local-cluster.sh. It is REFUSED by the node
# unless STELL_DEV_UNSAFE_TESTKEY=1, which --dev sets explicitly.
DEV_FAUCET_KEY="1111111111111111111111111111111111111111111111111111111111111111"
# A fixed, valid 32-byte workchain/masterchain recipient (no key needed).
RECIPIENT="$(printf '5a%.0s' $(seq 32))"

usage() {
    awk 'NR <= 2 { next } /^# =/ { exit } { sub(/^# ?/, ""); print }' "$0"
    exit "${1:-0}"
}

while (($# > 0)); do
    case "$1" in
        --duration) DURATION="${2:?--duration needs seconds}"; shift 2 ;;
        --duration=*) DURATION="${1#*=}"; shift ;;
        --interval) INTERVAL="${2:?--interval needs seconds}"; shift 2 ;;
        --interval=*) INTERVAL="${1#*=}"; shift ;;
        --amount) AMOUNT="${2:?--amount needs nano}"; shift 2 ;;
        --amount=*) AMOUNT="${1#*=}"; shift ;;
        --replays) REPLAYS="${2:?--replays needs a count}"; shift 2 ;;
        --replays=*) REPLAYS="${1#*=}"; shift ;;
        --base-dir) BASE="${2:?--base-dir needs a path}"; shift 2 ;;
        --base-dir=*) BASE="${1#*=}"; shift ;;
        --bin) BIN="${2:?--bin needs a path}"; shift 2 ;;
        --bin=*) BIN="${1#*=}"; shift ;;
        --dev) DEV=1; shift ;;
        --keep) KEEP=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "[soak] unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
done

log()  { printf '[soak %s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[soak %s] WARN: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
fail() {
    printf '[soak %s] FAIL: %s\n' "$(date +%H:%M:%S)" "$*" >&2
    exit 1
}

command -v curl >/dev/null || { echo "[soak] curl is required" >&2; exit 2; }
command -v jq   >/dev/null || { echo "[soak] jq is required" >&2; exit 2; }

# --- defaults / key source ---------------------------------------------------
if [[ -z "${STELL_FAUCET_KEY:-}" && -z "${STELL_FAUCET_KEY_FILE:-}" ]]; then
    if ((DEV == 1)); then
        STELL_FAUCET_KEY="$DEV_FAUCET_KEY"
        warn "using the PUBLIC dev faucet key (--dev); never do this on a live network"
    else
        echo "[soak] STELL_FAUCET_KEY (or STELL_FAUCET_KEY_FILE) is required: it must name" >&2
        echo "       the genesis-funded faucet seed the node was started with." >&2
        echo "       For a local throwaway chain only, rerun with --dev." >&2
        exit 2
    fi
fi
FAUCET_SOURCE_FILE=""
if [[ -n "${STELL_FAUCET_KEY_FILE:-}" && -z "${STELL_FAUCET_KEY:-}" ]]; then
    # The node accepts a 0600 file; the wallet CLI accepts the seed value. Read
    # it once here (never echo it) and keep the file reference for the node
    # env so the seed never lands in a process environment on a real run.
    [[ -r "$STELL_FAUCET_KEY_FILE" ]] || { echo "[soak] cannot read STELL_FAUCET_KEY_FILE" >&2; exit 2; }
    FAUCET_SOURCE_FILE="$(cd "$(dirname "$STELL_FAUCET_KEY_FILE")" && pwd)/$(basename "$STELL_FAUCET_KEY_FILE")"
    STELL_FAUCET_KEY="$(tr -d '[:space:]' < "$STELL_FAUCET_KEY_FILE")"
fi
[[ "$STELL_FAUCET_KEY" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "[soak] STELL_FAUCET_KEY must be a 32-byte hex seed (64 hex chars)" >&2
    exit 2
}

# --- binary ------------------------------------------------------------------
resolve_bin() {
    if [[ -n "$BIN" && -x "$BIN" ]]; then printf '%s\n' "$BIN"; return 0; fi
    local cand
    for cand in \
        "$ROOT/stellereum/target/release/stellereum" \
        "$ROOT/stellereum/target/debug/stellereum" \
        "$ROOT/target/release/stellereum" \
        "$ROOT/target/debug/stellereum"; do
        [[ -x "$cand" ]] && { printf '%s\n' "$cand"; return 0; }
    done
    cand="$(command -v stellereum || true)"
    [[ -n "$cand" ]] && { printf '%s\n' "$cand"; return 0; }
    return 1
}
BIN="$(resolve_bin)" || {
    echo "[soak] no stellereum binary found; build it (cargo build -p stellereum) or set STELL_BIN" >&2
    exit 2
}
case "$DURATION" in ''|*[!0-9]*) echo "[soak] duration must be whole seconds" >&2; exit 2 ;; esac
case "$INTERVAL" in ''|*[!0-9]*|0) echo "[soak] interval must be a positive whole number" >&2; exit 2 ;; esac

for ((i = 1; i <= 3; i++)); do
    for port in $((P2P_BASE + i)) $((RPC_BASE + i)) $((EXP_BASE + i)); do
        if ss -ltn 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; then
            fail "port $port is already in use (pick another --base or free it)"
        fi
    done
done

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$BASE/$RUN_ID"
mkdir -p "$RUN_DIR"

# --- cluster roles -----------------------------------------------------------
# Role -> index. `xpc` is the cross-shard exactly-once probe; alpha/beta are the
# independent determinism pair.
ROLES=(alpha beta xpc)
declare -A P2P RPC EXP DIR
for i in "${!ROLES[@]}"; do
    role="${ROLES[$i]}"
    n=$((i + 1))
    P2P[$role]=$((P2P_BASE + n))
    RPC[$role]=$((RPC_BASE + n))
    EXP[$role]=$((EXP_BASE + n))
    DIR[$role]="$RUN_DIR/$role"
    mkdir -p "${DIR[$role]}/data" "${DIR[$role]}/keys"
done

# --- helpers -----------------------------------------------------------------
rpc_raw() {
    local port="$1" method="$2" params="${3:-[]}"
    curl -sS -m 10 -X POST -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
        "http://127.0.0.1:$port"
}
rpc() {
    local port="$1" method="$2" params="${3:-[]}" resp
    resp="$(rpc_raw "$port" "$method" "$params")" || return 1
    if jq -e '.error != null' >/dev/null 2>&1 <<<"$resp"; then
        echo "[soak] rpc error ($method): $(jq -c '.error' <<<"$resp")" >&2
        return 1
    fi
    jq -c '.result' <<<"$resp"
}
shard_field() { # role shard field
    local role="$1" shard="$2" field="$3"
    rpc "${RPC[$role]}" stell_getShards '[]' \
        | jq -r --argjson s "$shard" --arg f "$field" \
            '.shards[] | select(.shard_id == $s) | .[$f] // empty' 2>/dev/null || true
}
shard_height() { shard_field "$1" "$2" tip_height; }
shard_root()   { shard_field "$1" "$2" state_root; }
root_at() { # role height (masterchain historical root, quorum-anchored)
    local role="$1" h="$2"
    rpc "${RPC[$role]}" stell_getHistoricalRoot "{\"height\":$h}" \
        | jq -r '.state_root // empty' 2>/dev/null || true
}
balance_of() { # role address -> "balance nonce"
    local role="$1" addr="$2"
    rpc "${RPC[$role]}" stell_getBalance "{\"address\":\"$addr\"}" \
        | jq -r '"\(.balance) \(.nonce)"'
}
pid_of() { cat "$1/node.pid" 2>/dev/null || true; }
alive() { local p; p="$(pid_of "$1")"; [[ -n "$p" ]] && kill -0 "$p" 2>/dev/null; }

tail_logs() {
    local role
    for role in "${ROLES[@]}"; do
        [[ -f "${DIR[$role]}/live.log" ]] || continue
        printf '\n----- %s live.log (tail) -----\n' "$role" >&2
        tail -n 40 "${DIR[$role]}/live.log" >&2 || true
    done
}

stop_role() {
    local role="$1" p
    p="$(pid_of "${DIR[$role]}")"
    [[ -n "$p" ]] || return 0
    if kill -0 "$p" 2>/dev/null; then
        kill "$p" 2>/dev/null || true
        for _ in $(seq 1 60); do kill -0 "$p" 2>/dev/null || break; sleep 0.2; done
        kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null || true
    fi
    rm -f "${DIR[$role]}/node.pid"
}

stop_all() {
    local role
    for role in "${ROLES[@]}"; do stop_role "$role"; done
}

on_exit() {
    local st=$?
    if ((st != 0)); then tail_logs; fi
    if [[ "$KEEP" == "1" ]]; then
        log "keeping processes and data under $RUN_DIR (SOAK_KEEP=1)"
    else
        stop_all
    fi
    exit "$st"
}
trap on_exit EXIT

# --- keygen + config ---------------------------------------------------------
log "binary: $BIN"
log "run dir: $RUN_DIR   duration=${DURATION}s interval=${INTERVAL}s amount=${AMOUNT}nano replays=$REPLAYS"

TEMPLATE="$RUN_DIR/template"
mkdir -p "$TEMPLATE/keys"
ident_out="$(STELL_KEY_PLAINTEXT=1 "$BIN" keys init --keys-dir "$TEMPLATE/keys" 2>&1)" || {
    printf '%s\n' "$ident_out" >&2
    fail "keys init failed"
}
ident_line="$(grep -oE 'NODE IDENTITY: .*' <<<"$ident_out" | head -1)"
[[ -n "$ident_line" ]] || fail "keys init printed no NODE IDENTITY line"
write_role() {
    local role="$1" dir="${DIR[$1]}"
    cp -a "$TEMPLATE/keys/." "$dir/keys/"
    cat > "$dir/node.yaml" <<EOF
name: soak
listen: "127.0.0.1:${P2P[$role]}"
advertise: "127.0.0.1:${P2P[$role]}"
# Empty list = solo/dev validator set: this process is its own sole validator
# (quorum 1). That is exactly what a deterministic two-cluster soak wants; a
# production multi-validator genesis lists the consensus ids instead.
validators: []
peers: []
EOF
    cat > "$dir/env" <<EOF
# Generated by scripts/soak_two_shard.sh — one process drives both shards.
STELL_SHARDS=0,1
STELL_KEY_PLAINTEXT=1
STELL_NEW_CHAIN=1
EOF
    if [[ -n "$FAUCET_SOURCE_FILE" ]]; then
        echo "STELL_FAUCET_KEY_FILE=$FAUCET_SOURCE_FILE" >> "$dir/env"
    else
        echo "STELL_FAUCET_KEY=$STELL_FAUCET_KEY" >> "$dir/env"
    fi
    cat >> "$dir/env" <<EOF
STELL_PURE_PQ=1
STELL_ROUND_TIMEOUT_MS=${SOAK_ROUND_TIMEOUT_MS:-5000}
STELL_BROADCAST_JOIN_MS=2000
STELL_CATCHUP_BUDGET_MS=8000
STELL_RPC_LISTEN=127.0.0.1:${RPC[$role]}
STELL_EXPLORER_LISTEN=127.0.0.1:${EXP[$role]}
EOF
    if ((DEV == 1)); then
        echo "STELL_DEV_UNSAFE_TESTKEY=1" >> "$dir/env"
    fi
    chmod 600 "$dir/env"
}

boot_role() {
    local role="$1" dir="${DIR[$1]}"
    ( cd "$dir" && set -a && . ./env && set +a && exec "$BIN" run --config node.yaml --shard 0 >> live.log 2>&1 ) &
    echo $! > "$dir/node.pid"
    log "booted $role (pid $(pid_of "$dir"), p2p=127.0.0.1:${P2P[$role]}, rpc=127.0.0.1:${RPC[$role]})"
}

for role in "${ROLES[@]}"; do write_role "$role"; done
# Phase order is deliberate: alpha+beta are the determinism pair, then xpc is
# the cross-shard probe. They do not run at the same time, so a single busy
# host never starves the in-process shard-1 task of one of three full nodes.
for role in alpha beta; do boot_role "$role"; done

wait_ready() {
    local role="$1" deadline=$((SECONDS + READY_TIMEOUT)) h0 h1 xpc_ready wc_ready
    while ((SECONDS < deadline)); do
        alive "${DIR[$role]}" || fail "$role died during startup (see log)"
        h0="$(shard_height "$role" 0)"
        h1="$(shard_height "$role" 1)"
        xpc_ready=0
        wc_ready=0
        grep -q 'cross-shard 2PC ACTIVE from height' "${DIR[$role]}/live.log" 2>/dev/null && xpc_ready=1
        grep -q 'workchain genesis' "${DIR[$role]}/live.log" 2>/dev/null && wc_ready=1
        # `>= 2` = the workchain finalized at least one REAL block, not just
        # its genesis head: a node whose shard-1 task never got scheduled must
        # fail readiness, not be mistaken for a healthy shard.
        if [[ -n "$h0" && -n "$h1" && "$h0" -ge 2 && "$h1" -ge 2 ]] \
            && ((xpc_ready == 1 && wc_ready == 1)); then
            log "$role ready: shard0=$h0 shard1=$h1"
            return 0
        fi
        sleep 2
    done
    ((xpc_ready == 1)) || fail "$role did not log '2PC ACTIVE' within ${READY_TIMEOUT}s (wrong binary: 2PC is not armed)"
    ((wc_ready == 1)) || fail "$role did not log 'workchain genesis' within ${READY_TIMEOUT}s (the shard-1 extra never started)"
    fail "$role did not advance BOTH shards within ${READY_TIMEOUT}s (shard0='${h0:-?}' shard1='${h1:-?}')"
}

for role in alpha beta; do wait_ready "$role"; done

# Derive the genesis-funded sender ONCE, without submitting anything, so the
# balance around each transfer can be read before the source is debited.
# Note: `stellereum wallet send-pq` (stellereum/src/cli/args.rs) currently only
# accepts `--falcon-seed` on the CLI (no `--key-file`/env fallback).
derive_sender() {
    local role="$1" out
    out="$("$BIN" wallet send-pq \
        --falcon-seed "$STELL_FAUCET_KEY" \
        --to "$RECIPIENT" \
        --amount 1 \
        --target-shard 1 \
        --rpc "http://127.0.0.1:${RPC[$role]}" \
        --dry-run 2>&1)" || {
        printf '%s\n' "$out" >&2
        fail "wallet dry-run failed on $role; cannot derive the funded sender"
    }
    grep -oE 'From: +[0-9a-fA-F]+' <<<"$out" | head -1 | awk '{print $NF}'
}
FAUCET_ADDR="$(derive_sender alpha)"
[[ -n "$FAUCET_ADDR" ]] || fail "could not derive the funded faucet address"

# --- transfer helpers --------------------------------------------------------
# The wallet CLI prints the submitted mempool hash; the receipt carries the
# canonical bincode raw bytes, which is exactly what `stell_sendRawTransaction`
# takes. Reusing those bytes across clusters makes the state inputs identical.
submit_wallet_tx() { # role target_shard -> "<tx_hash> <sender>"
    local role="$1" target="$2" out hash sender
    out="$("$BIN" wallet send-pq \
        --falcon-seed "$STELL_FAUCET_KEY" \
        --to "$RECIPIENT" \
        --amount "$AMOUNT" \
        --target-shard "$target" \
        --rpc "http://127.0.0.1:${RPC[$role]}" 2>&1)" || {
        printf '%s\n' "$out" >&2
        fail "wallet send-pq failed on $role"
    }
    hash="$(grep -oE 'mempool tx hash: [0-9a-fA-F]+' <<<"$out" | head -1 | awk '{print $NF}')"
    sender="$(grep -oE 'From: +[0-9a-fA-F]+' <<<"$out" | head -1 | awk '{print $NF}')"
    [[ -n "$hash" ]] || { printf '%s\n' "$out" >&2; fail "no tx hash in wallet output"; }
    [[ -n "$sender" ]] || { printf '%s\n' "$out" >&2; fail "no sender address in wallet output"; }
    printf '%s %s\n' "$hash" "$sender"
}

wait_receipt() { # role tx_hash -> prints compact receipt JSON
    local role="$1" hash="$2" deadline=$((SECONDS + TX_TIMEOUT)) rec status
    while ((SECONDS < deadline)); do
        rec="$(rpc "${RPC[$role]}" stell_getTransactionReceipt "{\"hash\":\"$hash\"}" 2>/dev/null || true)"
        if [[ -n "$rec" && "$rec" != "null" ]]; then
            status="$(jq -r '.status // empty' <<<"$rec" 2>/dev/null || true)"
            [[ "$status" == "failed" ]] && fail "transaction $hash FAILED on $role"
            if [[ "$status" == "success" ]] && jq -e '.raw_tx != null' >/dev/null 2>&1 <<<"$rec"; then
                printf '%s\n' "$rec"
                return 0
            fi
        fi
        alive "${DIR[$role]}" || fail "$role died while waiting for receipt $hash"
        sleep 1
    done
    fail "receipt for $hash did not become successful on $role within ${TX_TIMEOUT}s"
}

submit_raw() { # role raw_hex
    rpc "${RPC[$1]}" stell_sendRawTransaction "{\"tx\":\"$2\"}" >/dev/null 2>&1 || true
}

wait_nonce() { # role address expected deadline seconds
    local role="$1" addr="$2" want="$3" timeout="$4" deadline=$((SECONDS + $4)) got
    while ((SECONDS < deadline)); do
        read -r _ got <<<"$(balance_of "$role" "$addr")"
        [[ "$got" == "$want" ]] && return 0
        alive "${DIR[$role]}" || fail "$role died while waiting for nonce $want"
        sleep 1
    done
    fail "nonce of $addr on $role did not reach $want within ${timeout}s (got ${got:-?})"
}

credits_on_shard1() { # role
    local role="$1"
    { grep -oE 'cross-shard inbound credited [0-9]+ message\(s\) on shard 1' "${DIR[$role]}/live.log" 2>/dev/null \
        | awk '{s += $4} END {print s + 0}'; } || true
}

# Number of FINALIZED lines in the process log. One line is emitted per shard
# per finalized height; with `shard0_height` this gives a lower-bound progress
# signal for the workchain when the in-memory shard-head registry lags.
finalized_count() { # role
    grep -c 'FINALIZED block #' "${DIR[$1]}/live.log" 2>/dev/null || true
}

wait_credits() { # role expected timeout
    local role="$1" want="$2" timeout="$3" deadline=$((SECONDS + $3)) got
    while ((SECONDS < deadline)); do
        got="$(credits_on_shard1 "$role")"
        ((got > want)) && fail "$role credited $got shard-1 messages, expected exactly $want (duplicate credit)"
        [[ "$got" == "$want" ]] && return 0
        alive "${DIR[$role]}" || fail "$role died while waiting for target credit"
        sleep 1
    done
    fail "$role did not reach $want shard-1 credits within ${timeout}s (got ${got:-?})"
}

# --- shared per-tick checks --------------------------------------------------
declare -A LAST_H0 LAST_H1 LAST_PROG

reset_progress() {
    local role
    LAST_H0=(); LAST_H1=(); LAST_PROG=()
    for role in "$@"; do
        LAST_H0[$role]="$(shard_height "$role" 0)"
        LAST_H1[$role]="$(shard_height "$role" 1)"
        LAST_PROG[$role]=$(( $(finalized_count "$role") - LAST_H0[$role] ))
    done
}

check_heights() { # roles...
    local role h0 h1 prog
    for role in "$@"; do
        h0="$(shard_height "$role" 0)"
        h1="$(shard_height "$role" 1)"
        [[ -n "$h0" && -n "$h1" ]] || fail "$role stopped reporting a shard head (shard0='$h0' shard1='$h1')"
        ((h0 > LAST_H0[$role])) || fail "$role shard0 stalled at $h0 (was ${LAST_H0[$role]})"
        LAST_H0[$role]="$h0"
        if ((h1 > LAST_H1[$role])); then
            LAST_H1[$role]="$h1"
            LAST_PROG[$role]=$(( $(finalized_count "$role") - h0 ))
        else
            # Fallback evidence: the workchain's own FINALIZED lines. A truly
            # stalled shard produces neither a new head nor new finalizations.
            prog=$(( $(finalized_count "$role") - h0 ))
            ((prog > LAST_PROG[$role])) \
                || fail "$role shard1 stalled (head $h1 was ${LAST_H1[$role]}; workchain finalizations $prog was ${LAST_PROG[$role]})"
            warn "$role published shard1 head $h1 is behind its ${prog} workchain finalizations; treating the workchain as advancing (registry lag)"
            LAST_PROG[$role]="$prog"
        fi
    done
}

compare_pair_roots() {
    local h_common h_cmp ra rb r1a r1b
    h_common=$(( LAST_H0[alpha] < LAST_H0[beta] ? LAST_H0[alpha] : LAST_H0[beta] ))
    h_cmp=$((h_common > 2 ? h_common - 2 : 1))
    if ((h_cmp >= 1 && h_cmp > LAST_INC)); then
        ra="$(root_at alpha "$h_cmp")"
        rb="$(root_at beta "$h_cmp")"
        [[ -n "$ra" && -n "$rb" ]] || fail "could not read shard0 root at height $h_cmp (alpha='$ra' beta='$rb')"
        [[ "$ra" == "$rb" ]] || fail "shard0 ROOT DIVERGED at height $h_cmp: alpha=$ra beta=$rb"
        r1a="$(shard_root alpha 1)"
        r1b="$(shard_root beta 1)"
        [[ -n "$r1a" && -n "$r1b" ]] || fail "could not read shard1 root (alpha='$r1a' beta='$r1b')"
        [[ "$r1a" == "$r1b" ]] || fail "shard1 ROOT DIVERGED: alpha=$r1a beta=$r1b"
        log "roots match at shard0 height $h_cmp (${ra:0:16}…) and shard1 (${r1a:0:16}…)"
    else
        log "root comparison deferred: common height $h_cmp is not above the last inclusion $LAST_INC"
    fi
}

# =============================================================================
# Phase 1 — INDEPENDENTLY BUILT DETERMINISM PAIR (alpha + beta)
# =============================================================================
PHASE1_SECS=$((DURATION / 2))
PHASE1_END=$((SECONDS + PHASE1_SECS))

reset_progress alpha beta
# Highest block height at which the determinism pair included the last
# same-shard transfer. Roots may only be compared ABOVE this height: below it
# one cluster may have applied the transfer and the other not yet.
LAST_INC=0
tick=0

log "phase 1/2: determinism pair alpha+beta for ~${PHASE1_SECS}s"
while ((SECONDS < PHASE1_END)); do
    tick=$((tick + 1))
    sleep_for=$INTERVAL
    ((SECONDS + sleep_for > PHASE1_END)) && sleep_for=$((PHASE1_END - SECONDS))
    ((sleep_for > 0)) && sleep "$sleep_for"

    check_heights alpha beta
    log "tick $tick: heights alpha=${LAST_H0[alpha]}/${LAST_H1[alpha]} beta=${LAST_H0[beta]}/${LAST_H1[beta]}"

    # Independent clusters agree at a COMMON masterchain height. The shard-1
    # state in this pair is genesis-only (no cross-shard traffic is sent to
    # it), so its published root is comparable directly.
    compare_pair_roots

    # Same-shard transfer seeded into BOTH clusters from the SAME signed
    # bytes. This keeps the comparison above meaningful across the whole run.
    read -r txh tx_sender <<<"$(submit_wallet_tx alpha 0)"
    [[ "$tx_sender" == "$FAUCET_ADDR" ]] || fail "wallet sender $tx_sender != derived faucet $FAUCET_ADDR"
    rec="$(wait_receipt alpha "$txh")"
    raw="$(jq -r '.raw_tx' <<<"$rec")"
    [[ -n "$raw" && "$raw" != "null" ]] || fail "receipt for $txh carries no raw_tx"
    submit_raw beta "$raw"
    rec_beta="$(wait_receipt beta "$txh")"
    inc_a="$(jq -r '.height' <<<"$rec")"
    inc_b="$(jq -r '.height' <<<"$rec_beta")"
    LAST_INC=$(( inc_a > inc_b ? inc_a : inc_b ))
    read -r _ nonce_a <<<"$(balance_of alpha "$FAUCET_ADDR")"
    wait_nonce beta "$FAUCET_ADDR" "$nonce_a" "$TX_TIMEOUT"
done

# Final determinism checkpoint: wait until a common height ABOVE the last
# inclusion, then compare the roots one last time.
final_deadline=$((SECONDS + TX_TIMEOUT))
h_cmp=0
while ((SECONDS < final_deadline)); do
    h0a="$(shard_height alpha 0)"
    h0b="$(shard_height beta 0)"
    h_common=$(( h0a < h0b ? h0a : h0b ))
    h_cmp=$((h_common > 2 ? h_common - 2 : 1))
    ((h_cmp > LAST_INC)) && break
    sleep 2
done
if ((h_cmp >= 1 && h_cmp > LAST_INC)); then
    ra="$(root_at alpha "$h_cmp")"
    rb="$(root_at beta "$h_cmp")"
    [[ -n "$ra" && "$ra" == "$rb" ]] || fail "final shard0 root divergence at height $h_cmp (alpha='$ra' beta='$rb')"
    log "final determinism roots match at shard0 height $h_cmp"
else
    fail "no common height above the last inclusion ($LAST_INC) for the final root check"
fi

stop_role alpha
stop_role beta
log "phase 1 done: both shards advanced and alpha/beta roots matched; pair stopped"

# =============================================================================
# Phase 2 — CROSS-SHARD 2PC EXACTLY-ONCE (xpc, alone)
# =============================================================================
boot_role xpc
wait_ready xpc
xaddr="$(derive_sender xpc)"
[[ "$xaddr" == "$FAUCET_ADDR" ]] || fail "xpc derives sender $xaddr, determinism pair used $FAUCET_ADDR"

reset_progress xpc
transfers=0
PHASE2_SECS=$((DURATION / 2))
PHASE2_END=$((SECONDS + PHASE2_SECS))
log "phase 2/2: cross-shard exactly-once on xpc for ~${PHASE2_SECS}s"
while ((SECONDS < PHASE2_END)); do
    tick=$((tick + 1))
    sleep_for=$INTERVAL
    ((SECONDS + sleep_for > PHASE2_END)) && sleep_for=$((PHASE2_END - SECONDS))
    ((sleep_for > 0)) && sleep "$sleep_for"

    check_heights xpc
    log "tick $tick: heights xpc=${LAST_H0[xpc]}/${LAST_H1[xpc]}"

    transfers=$((transfers + 1))
    read -r before_x nonce_x0 <<<"$(balance_of xpc "$FAUCET_ADDR")"
    read -r xh xsender <<<"$(submit_wallet_tx xpc 1)"
    [[ "$xsender" == "$FAUCET_ADDR" ]] || fail "wallet sender $xsender != derived faucet $FAUCET_ADDR"
    xrec="$(wait_receipt xpc "$xh")"
    xraw="$(jq -r '.raw_tx' <<<"$xrec")"
    fee="$(jq -r '.fee_charged' <<<"$xrec")"
    [[ -n "$xraw" && "$xraw" != "null" ]] || fail "receipt for $xh carries no raw_tx"
    # Replay the SAME bytes: exactly-once must survive duplicate delivery.
    for ((r = 0; r < REPLAYS; r++)); do submit_raw xpc "$xraw"; done
    wait_nonce xpc "$xsender" $((nonce_x0 + 1)) "$TX_TIMEOUT"
    read -r after_x nonce_x1 <<<"$(balance_of xpc "$xsender")"
    ((nonce_x1 == nonce_x0 + 1)) || fail "cross-shard replay advanced the nonce by $((nonce_x1 - nonce_x0)), expected 1"
    expected_debit=$((AMOUNT + fee))
    actual_debit=$((before_x - after_x))
    ((actual_debit == expected_debit)) \
        || fail "cross-shard source debit $actual_debit != amount($AMOUNT)+fee($fee)=$expected_debit"
    # Wait until the target credits exactly this transfer, then require the
    # cumulative count to be EXACTLY the number of transfers done.
    wait_credits xpc "$transfers" "$TX_TIMEOUT"
    log "tick $tick: cross-shard transfer $transfers landed exactly once (debit=$actual_debit, credits=$transfers)"
done

got="$(credits_on_shard1 xpc)"
[[ "$got" == "$transfers" ]] \
    || fail "final cross-shard credit count $got != transfers $transfers (duplicate or missing credit)"

log "PASS: ${DURATION}s active soak (~$((DURATION/2))s per phase), ${SECONDS}s wall clock, $tick ticks, $transfers cross-shard transfers, every shard advanced, alpha/beta roots identical, every transfer credited exactly once"
log "run dir: $RUN_DIR (processes stopped unless SOAK_KEEP=1)"
exit 0
