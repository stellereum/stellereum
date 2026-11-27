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
FALLBACK_RPCS="${STELL_FALLBACK_RPCS:-http://127.0.0.1:8546}"
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

rpc() {
    curl -s -m 8 -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}" "$1" 2>/dev/null || true
}

json_extract_result() {
    local payload="$1"
    [ -n "$payload" ] || return 1
    if command -v python3 >/dev/null 2>&1; then
        python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(d, dict) or d.get("error") is not None:
    sys.exit(1)
r = d.get("result")
if r is None:
    sys.exit(1)
if isinstance(r, bool):
    print("true" if r else "false")
elif isinstance(r, (int, float, str)):
    print(r)
else:
    print(json.dumps(r))
' <<<"$payload" 2>/dev/null
        return $?
    fi
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$payload" | jq -er 'select(.error == null and .result != null) | .result' 2>/dev/null
        return $?
    fi
    local val
    val="$(printf '%s' "$payload" | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
    [ -n "$val" ] || return 1
    printf '%s\n' "$val"
}

validator_status_field() { # $1 json payload, $2 field
    local payload="$1" field="$2"
    [ -n "$payload" ] || return 1
    if command -v python3 >/dev/null 2>&1; then
        python3 -c '
import json, sys
field = sys.argv[1]
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(d, dict) or d.get("error") is not None:
    sys.exit(1)
r = d.get("result")
if not isinstance(r, dict):
    sys.exit(1)
v = r.get(field)
if v is None:
    print("")
elif isinstance(v, bool):
    print("true" if v else "false")
else:
    print(v)
' "$field" <<<"$payload" 2>/dev/null
        return $?
    fi
    if command -v jq >/dev/null 2>&1; then
        printf '%s' "$payload" | jq -er --arg f "$field" \
            'select(.error == null and (.result | type == "object")) | (.result[$f] // "") | tostring' 2>/dev/null
        return $?
    fi
    printf '%s' "$payload" | sed -n "s/.*\"${field}\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" | head -n1
}

rpc_node() { # transport target port method params
    local transport="$1" target="$2" port="$3" method="$4" params="$5"
    if [ "$transport" = local ]; then
        rpc "http://127.0.0.1:8546" "$method" "$params"
    else
        local payload="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}"
        ssh -p "$port" -o ConnectTimeout=8 -o BatchMode=yes "$target" \
            "curl -s -m 4 -H 'content-type: application/json' -d $(printf '%q' "$payload") http://127.0.0.1:8545" 2>/dev/null || true
    fi
}

query_with_fallback() { # method params [prefer_transport prefer_target prefer_port]
    local method="$1" params="$2" p_tr="${3:-}" p_tgt="${4:-}" p_port="${5:-}"
    local resp url fb_list row r_name r_tr r_tgt r_port r_dir r_vid

    resp="$(rpc "$PUBLIC_RPC" "$method" "$params")"
    if json_extract_result "$resp" >/dev/null 2>&1; then
        printf '%s' "$resp"
        return 0
    fi

    fb_list="${FALLBACK_RPCS//,/ }"
    for url in $fb_list; do
        [ -n "$url" ] || continue
        [ "$url" = "$PUBLIC_RPC" ] && continue
        resp="$(rpc "$url" "$method" "$params")"
        if json_extract_result "$resp" >/dev/null 2>&1; then
            printf '%s' "$resp"
            return 0
        fi
    done

    if [ -n "$p_tr" ]; then
        resp="$(rpc_node "$p_tr" "$p_tgt" "$p_port" "$method" "$params")"
        if json_extract_result "$resp" >/dev/null 2>&1; then
            printf '%s' "$resp"
            return 0
        fi
    fi

    for row in "${NODES[@]}"; do
        IFS='|' read -r r_name r_tr r_tgt r_port r_dir r_vid <<<"$row"
        resp="$(rpc_node "$r_tr" "$r_tgt" "$r_port" "$method" "$params")"
        if json_extract_result "$resp" >/dev/null 2>&1; then
            printf '%s' "$resp"
            return 0
        fi
    done
    return 1
}

tip() {
    local resp raw
    resp="$(query_with_fallback stell_blockNumber '[]' || true)"
    raw="$(json_extract_result "$resp" 2>/dev/null || true)"
    parse_uint_or_hex "$raw" 2>/dev/null || true
}

fetch_validator_status() { # validator [transport target port]
    local vid="$1" tr="${2:-}" tgt="${3:-}" port="${4:-}"
    query_with_fallback stell_getValidatorStatus "{\"validator\":\"$vid\"}" "$tr" "$tgt" "$port"
}

node_height() { # transport target port
    local transport="$1" target="$2" port="$3" resp raw
    resp="$(rpc_node "$transport" "$target" "$port" stell_blockNumber '[]')"
    raw="$(json_extract_result "$resp" 2>/dev/null || true)"
    parse_uint_or_hex "$raw" 2>/dev/null || true
}

check_withdrawal_key() { # transport target port dir
    local transport="$1" target="$2" port="$3" dir="$4"
    local key_path="$dir/keys/withdrawal.key"
    if [ "$transport" = local ]; then
        [ -f "$key_path" ] && [ -r "$key_path" ]
    else
        ssh -p "$port" -o ConnectTimeout=8 -o BatchMode=yes "$target" \
            "test -f $(printf '%q' "$key_path") && test -r $(printf '%q' "$key_path")" 2>/dev/null
    fi
}

do_unjail() { # transport target port dir validator rpc
    local transport="$1" target="$2" port="$3" dir="$4" vid="$5" rpc_url="$6"
    local suffix q_dir q_parent q_suffix q_vid q_rpc cmd rc=0
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
        rc=${PIPESTATUS[0]}
    else
        ssh -p "$port" -o ConnectTimeout=10 -o BatchMode=yes "$target" "$cmd" 2>&1 | tail -n 4
        rc=${PIPESTATUS[0]}
    fi
    return "$rc"
}

pass() {
    local t; t="$(tip)"
    if [[ ! "$t" =~ ^[0-9]+$ ]]; then
        echo "[auto-unjail] all RPC endpoints unreachable or invalid height; skipping pass"
        return 0
    fi
    t=$((10#$t))
    for row in "${NODES[@]}"; do
        IFS='|' read -r name transport target port dir vid <<<"$row"
        local status_json jailed rel waddr
        status_json="$(fetch_validator_status "$vid" "$transport" "$target" "$port" || true)"
        if [ -z "$status_json" ]; then
            echo "[auto-unjail] $name: could not read stell_getValidatorStatus from any RPC; skipping"
            continue
        fi
        jailed="$(validator_status_field "$status_json" jailed 2>/dev/null || true)"
        [ "$jailed" = "true" ] || continue
        rel="$(validator_status_field "$status_json" release_height 2>/dev/null || true)"
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
        waddr="$(validator_status_field "$status_json" withdrawal_address 2>/dev/null || true)"
        if [ -z "$waddr" ] || [ "$waddr" = "null" ] || [ "$waddr" = "None" ]; then
            echo "[auto-unjail] $name jailed and release passed, but withdrawal_address is unset; claim cold withdrawal address first"
            continue
        fi
        if ! check_withdrawal_key "$transport" "$target" "$port" "$dir"; then
            echo "[auto-unjail] $name jailed and release passed, but $dir/keys/withdrawal.key is missing or unreadable on target; skipping"
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
            echo "[auto-unjail] DRY RUN: would unjail $name (tip=$t release=$rel local=$h gap=$gap withdrawal=$waddr)"
            continue
        fi
        echo "[auto-unjail] unjailing $name (tip=$t release=$rel local=$h gap=$gap)"
        local rpc_url="http://127.0.0.1:8545"
        [ "$transport" = local ] && rpc_url="http://127.0.0.1:8546"
        local unjail_rc=0
        if do_unjail "$transport" "$target" "$port" "$dir" "$vid" "$rpc_url"; then
            unjail_rc=0
        else
            unjail_rc=$?
        fi
        if [ "$unjail_rc" -ne 0 ]; then
            echo "[auto-unjail] ERROR: unjail command for $name failed (exit $unjail_rc); cooldown not updated" >&2
            continue
        fi
        date +%s > "$stamp"
        local verify_attempt post_json post_jailed="unknown" post_in_set="unknown"
        for verify_attempt in 1 2 3 4 5; do
            sleep 1
            post_json="$(fetch_validator_status "$vid" "$transport" "$target" "$port" || true)"
            if [ -n "$post_json" ]; then
                post_jailed="$(validator_status_field "$post_json" jailed 2>/dev/null || echo "unknown")"
                post_in_set="$(validator_status_field "$post_json" in_set 2>/dev/null || echo "unknown")"
                if [ "$post_jailed" = "false" ]; then
                    break
                fi
            fi
        done
        echo "[auto-unjail] post-unjail status for $name: jailed=$post_jailed in_set=$post_in_set"
    done
}

if [ "$LOOP" -gt 0 ]; then
    while true; do pass; sleep "$LOOP"; done
else
    pass
fi
