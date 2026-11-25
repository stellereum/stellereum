#!/usr/bin/env bash
# auto-unjail.sh — return jailed validators to the set as soon as their jail
# expires, without a human in the loop.
#
# WHY: with STELL_MIN_BLOCK_MS=400 the jail budget is 42 misses = 16.8 s, so a
# single host hiccup (a co-located build, a rental neighbour) jails a validator
# for release_height - jailed_at = 4000 blocks — about 20 minutes of lost
# participation. Until then the MANUAL unjail (cold key) was the only way back,
# which meant the set stayed below 4/4 until an operator noticed.
#
# SAFETY RAILS (all deliberate):
#   * only `validator unjail` is ever executed — never start/stop/slash;
#   * the chain must have passed `release_height` AND the node must be within
#     MAX_GAP blocks of the tip, so it can vote immediately instead of being
#     re-jailed for missing the height it was unjailed at;
#   * each validator is attempted at most once per COOLDOWN seconds;
#   * `--dry-run` prints the decision without signing anything;
#   * every action is logged with tip, release height, local height and gap.
#
# Usage:
#   auto-unjail.sh              one pass (systemd timer friendly)
#   auto-unjail.sh --loop 60    loop with 60 s sleep
#   auto-unjail.sh --dry-run    decide, do not sign
#
# The cold withdrawal key stays on its own node; this script only invokes the
# local CLI there (or on this host for nodeB), it never copies key material.
set -u

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PUBLIC_RPC="${STELL_PUBLIC_RPC:-https://rpc.stellereum.org}"
MAX_GAP="${AUTO_UNJAIL_MAX_GAP:-20}"
COOLDOWN="${AUTO_UNJAIL_COOLDOWN:-300}"
STATE_DIR="${AUTO_UNJAIL_STATE_DIR:-${XDG_RUNTIME_DIR:-$HOME/.local/state}/stellereum-auto-unjail}"
DRY=0
LOOP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1; shift ;;
        --loop) LOOP="${2:?--loop needs seconds}"; shift 2 ;;
        --once) LOOP=0; shift ;;
        -h|--help) sed -n '1,30p' "$0"; exit 0 ;;
        *) echo "auto-unjail.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done

[[ "$LOOP" =~ ^[0-9]+$ ]] || { echo "auto-unjail.sh: --loop must be a non-negative integer" >&2; exit 2; }
[[ "$MAX_GAP" =~ ^[0-9]+$ ]] || { echo "auto-unjail.sh: AUTO_UNJAIL_MAX_GAP must be a non-negative integer" >&2; exit 2; }
[[ "$COOLDOWN" =~ ^[0-9]+$ ]] || { echo "auto-unjail.sh: AUTO_UNJAIL_COOLDOWN must be a non-negative integer" >&2; exit 2; }

mkdir -p -m 0700 "$STATE_DIR"
chmod 0700 "$STATE_DIR" 2>/dev/null || true

# Node table: name | transport (local|ssh) | target | port | node dir | validator id
NODES=(
  "B|local|||/home/imm/stellereum-project/multinode/nodeB|5762c3311356235a098ed7bc49026cf8f91ba9376f099ef2c7deabeadea88c5a"
  "A|ssh|root@212.113.103.105|22|/root/nodeA|48fd69d17c36d5391b7786f8091bce75e55f5b013344b60874090d53e8e8cdf7"
  "C|ssh|root@213.21.246.5|2222|/root/nodeC|9865d36eb93458ad7739e4de969e8c62b88e662b86f8ec38bd6ff3f83008162f"
  "D|ssh|root@138.124.102.200|22|/root/nodeD|df3d10f3549f492fa829553f9f0a1fe4e6daaf7a74aa532b5411db6eca6d2ba4"
)

parse_uint_or_hex() {
    local val="$1"
    if [[ "$val" =~ ^0[xX][0-9a-fA-F]+$ ]]; then
        printf '%d\n' "$((16#${val:2}))"
    elif [[ "$val" =~ ^[0-9]+$ ]]; then
        printf '%d\n' "$((10#$val))"
    else
        return 1
    fi
}

rpc() { curl -s -m 8 -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$1"; }
tip() {
    local raw
    raw="$(rpc "$PUBLIC_RPC" stell_blockNumber '[]' | sed -n 's/.*"result":"\([^"]*\)".*/\1/p' | head -n1)"
    parse_uint_or_hex "$raw" 2>/dev/null || true
}

status_field() { # $1 validator, $2 field
    rpc "$PUBLIC_RPC" stell_getValidatorStatus "{\"validator\":\"$1\"}" |
        python3 -c "import sys,json
r=json.load(sys.stdin).get('result') or {}
print(r.get('$2'))" 2>/dev/null
}

node_height() { # transport target port
    local transport="$1" target="$2" port="$3" raw
    if [ "$transport" = local ]; then
        raw="$(rpc "http://127.0.0.1:8546" stell_blockNumber '[]' | sed -n 's/.*"result":"\([^"]*\)".*/\1/p' | head -n1)"
    else
        raw="$(ssh -p "$port" -o ConnectTimeout=8 -o BatchMode=yes "$target" \
            "curl -s -m 4 -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_blockNumber\",\"params\":[]}' http://127.0.0.1:8545" |
            sed -n 's/.*"result":"\([^"]*\)".*/\1/p' | head -n1)"
    fi
    parse_uint_or_hex "$raw" 2>/dev/null || true
}

do_unjail() { # transport target port dir validator rpc
    local transport="$1" target="$2" port="$3" dir="$4" vid="$5" rpc_url="$6"
    local suffix q_dir q_parent q_suffix q_vid q_rpc cmd
    suffix="$(basename "$dir" | sed 's/^node//')"
    q_dir="$(printf '%q' "$dir")"
    q_parent="$(printf '%q' "$(dirname "$dir")")"
    q_suffix="$(printf '%q' "$suffix")"
    q_vid="$(printf '%q' "$vid")"
    q_rpc="$(printf '%q' "$rpc_url")"
    local cli="$q_dir/stellereum"
    if [ "$transport" = local ] && [ -x "$ROOT_DIR/target/release/stellereum" ]; then
        cli="$(printf '%q' "$ROOT_DIR/target/release/stellereum")"
    fi
    cmd="set -a; if [ -f $q_dir/env.$q_suffix ]; then . $q_dir/env.$q_suffix; elif [ -f $q_parent/env.$q_suffix ]; then . $q_parent/env.$q_suffix; fi; set +a; $cli validator unjail --withdrawal-key-file $q_dir/keys/withdrawal.key --validator-id $q_vid --rpc $q_rpc"
    if [ "$transport" = local ]; then
        bash -c "$cmd" 2>&1 | tail -n 4
    else
        ssh -p "$port" -o ConnectTimeout=10 -o BatchMode=yes "$target" "$cmd" 2>&1 | tail -n 4
    fi
}

pass() {
    local t; t="$(tip)"
    if [[ ! "$t" =~ ^[0-9]+$ ]]; then
        echo "[auto-unjail] public RPC unreachable or invalid height; skipping pass"
        return 0
    fi
    t=$((10#$t))
    for row in "${NODES[@]}"; do
        IFS='|' read -r name transport target port dir vid <<<"$row"
        local jailed rel
        jailed="$(status_field "$vid" jailed)"
        [ "$jailed" = "True" ] || continue
        rel="$(status_field "$vid" release_height)"
        if [[ "$rel" =~ ^0[xX][0-9a-fA-F]+$ ]]; then
            rel=$((16#${rel:2}))
        elif [[ "$rel" =~ ^[0-9]+$ ]]; then
            rel=$((10#$rel))
        else
            continue
        fi
        if [ "$t" -lt "$rel" ]; then
            echo "[auto-unjail] $name jailed; waiting for release $rel (tip $t, $((rel - t)) blocks)"
            continue
        fi
        local stamp="$STATE_DIR/$name.last"
        if [ -f "$stamp" ]; then
            local last_ts age
            last_ts="$(cat "$stamp" 2>/dev/null || true)"
            [[ "$last_ts" =~ ^[0-9]+$ ]] || last_ts=0
            age=$(( $(date +%s) - last_ts ))
            if [ "$age" -lt "$COOLDOWN" ]; then
                echo "[auto-unjail] $name jailed, release passed, attempted ${age}s ago (cooldown ${COOLDOWN}s)"
                continue
            fi
        fi
        local h; h="$(node_height "$transport" "$target" "$port")"
        if [[ ! "$h" =~ ^[0-9]+$ ]]; then
            echo "[auto-unjail] $name jailed but its local RPC does not answer; not unjailing a dead node"
            continue
        fi
        h=$((10#$h))
        local gap=$((t - h))
        # A NEGATIVE gap means the node is AHEAD of the public reference tip
        # (the reference lags a little): that is a synced node, not a suspicious
        # one. Only a large negative gap (a different chain / bogus reference)
        # is refused.
        if [ "$gap" -gt "$MAX_GAP" ] || [ "$gap" -lt -50 ]; then
            echo "[auto-unjail] $name jailed, release passed, but gap=$gap outside [-50, $MAX_GAP]; waiting"
            continue
        fi
        if [ "$DRY" = 1 ]; then
            echo "[auto-unjail] DRY RUN: would unjail $name (tip=$t release=$rel local=$h gap=$gap)"
            continue
        fi
        echo "[auto-unjail] unjailing $name (tip=$t release=$rel local=$h gap=$gap)"
        date +%s > "$stamp"
        local rpc_url="http://127.0.0.1:8545"
        [ "$transport" = local ] && rpc_url="http://127.0.0.1:8546"
        do_unjail "$transport" "$target" "$port" "$dir" "$vid" "$rpc_url"
    done
}

if [ "$LOOP" -gt 0 ]; then
    while true; do pass; sleep "$LOOP"; done
else
    pass
fi
