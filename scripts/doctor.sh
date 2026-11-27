#!/bin/sh
# ==============================================================================
# doctor.sh — diagnose ONE Stellereum node, locally.
#
# Run it ON the node (it only reads local state) — or let stell-sync.sh
# doctor <node> run it over ssh.
#
# WHAT IT ANSWERS (the questions that actually mattered during the outage):
#   * is my CONFIG in line with the expected cluster config? (name every
#     difference — a mixed-config cluster is what killed the chain)
#   * how many inodes are left? (Node C hit 655360/655360 and went read-only,
#     silently dropping out of consensus)
#   * how many ORPHAN CHUNK files am I holding? (463589 of them on Node C)
#   * what CONSENSUS CHECKPOINT do I carry? (height/round/locked hash — a stale
#     lock at round 56 with peers at round 0 means the node can never rejoin)
#   * which PUBSUB TOPIC am I on? (a node with STELL_SHARDS=0 sits on a
#     different topic and never exchanges a single message)
#   * which BINARY am I running, and is it inside a cargo target dir? (a
#     'cargo clean' deletes it under the live node -> 203/EXEC crash-loop)
#   * are my KEYS encrypted or plaintext?
#   * what CHAIN ID am I on?
#
# Usage:
#   doctor.sh [--dir /root/nodeC] [--service stell-nodeC.service]
#             [--scope system|user] [--json] [--quiet]
#
# POSIX sh. Read-only. Non-interactive. Safe to run on a live node.
# ==============================================================================

set -u

# --- defaults (override from the environment or the flags) ------------------
DOCTOR_DIR="${STELL_DOCTOR_DIR:-}"
DOCTOR_SERVICE="${STELL_DOCTOR_SERVICE:-}"
DOCTOR_SCOPE="${STELL_DOCTOR_SCOPE:-system}"
DOCTOR_RPC="${STELL_DOCTOR_RPC:-}"
DOCTOR_SHARD_ID="${STELL_DOCTOR_SHARD_ID:-0}"
DOCTOR_JSON=0
DOCTOR_QUIET=0

# The cluster conf (optional): it carries the expected values AND the topology.
STELL_CONF="${STELL_CONF:-/home/imm/stellereum-project/scripts/cluster-nodes.conf}"

usage() {
    cat <<EOF
doctor.sh — diagnose one Stellereum node

USAGE
  doctor.sh [options]

OPTIONS
  --dir DIR          the node's working directory (the one with data/ and keys/)
  --service NAME    the systemd unit that runs the node
  --scope system|user  which systemd manager owns the unit (default: system)
  --rpc URL         the node's RPC URL (default: derived from the env file)
  --shard-id N      the shard the node validates (default: 0)
  --json            machine-readable output
  --quiet           only the problems, no report
  --help            this text

ENVIRONMENT
  STELL_CONF        the cluster topology/expectations file (optional)
  STELOPS_BIN       the ops tool that reads the store (checkpoint/genesis root)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dir) [ $# -ge 2 ] || { echo "doctor.sh: --dir requires an argument" >&2; exit 2; }; DOCTOR_DIR="$2"; shift 2 ;;
        --service) [ $# -ge 2 ] || { echo "doctor.sh: --service requires an argument" >&2; exit 2; }; DOCTOR_SERVICE="$2"; shift 2 ;;
        --scope) [ $# -ge 2 ] || { echo "doctor.sh: --scope requires an argument" >&2; exit 2; }; DOCTOR_SCOPE="$2"; shift 2 ;;
        --rpc) [ $# -ge 2 ] || { echo "doctor.sh: --rpc requires an argument" >&2; exit 2; }; DOCTOR_RPC="$2"; shift 2 ;;
        --shard-id) [ $# -ge 2 ] || { echo "doctor.sh: --shard-id requires an argument" >&2; exit 2; }; DOCTOR_SHARD_ID="$2"; shift 2 ;;
        --json) DOCTOR_JSON=1; shift ;;
        --quiet) DOCTOR_QUIET=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "doctor.sh: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -r "$STELL_CONF" ]; then
    # shellcheck disable=SC1090
    . "$STELL_CONF"
fi

EXPECT_STELL_SHARDS="${EXPECT_STELL_SHARDS:-0}"
EXPECT_STELL_ROUND_TIMEOUT_MS="${EXPECT_STELL_ROUND_TIMEOUT_MS:-5000}"
EXPECT_STELL_DOWN_PROPOSER_TIMEOUT_MS="${EXPECT_STELL_DOWN_PROPOSER_TIMEOUT_MS:-800}"
EXPECT_STELL_MIN_BLOCK_MS="${EXPECT_STELL_MIN_BLOCK_MS:-400}"
EXPECT_STELL_KEEP_BLOCKS="${EXPECT_STELL_KEEP_BLOCKS:-8000}"
EXPECT_STELL_ARCHIVE="${EXPECT_STELL_ARCHIVE:-0}"
EXPECT_STELL_CHAIN_ID="${EXPECT_STELL_CHAIN_ID:-5757}"
EXPECT_BASE_FEE="${EXPECT_BASE_FEE:-280000}"
INODE_WARN_PCT="${INODE_WARN_PCT:-70}"
INODE_HARD_PCT="${INODE_HARD_PCT:-85}"
ORPHAN_WARN_COUNT="${ORPHAN_WARN_COUNT:-20000}"

STELOPS_BIN="${STELOPS_BIN:-/home/imm/stellereum-project/scripts/tools/stelops/target/release/stelops}"
STELOPS_REMOTE="${STELOPS_REMOTE:-/root/stelops}"

DOCTOR_TMPDIR=""
cleanup_tmp() {
    [ -n "${DOCTOR_TMPDIR:-}" ] && rm -rf "$DOCTOR_TMPDIR"
}
trap cleanup_tmp EXIT INT TERM

json_escape() {
    case "$1" in
        *\\*|*\"*|*[![:print:]]*)
            printf '%s' "$1" | awk '
                BEGIN { ORS = "" }
                {
                    if (NR > 1) printf "\\n"
                    gsub(/\\/, "\\\\")
                    gsub(/"/, "\\\"")
                    gsub(/\r/, "\\r")
                    gsub(/\t/, "\\t")
                    gsub(/\b/, "\\b")
                    gsub(/\f/, "\\f")
                    printf "%s", $0
                }
            '
            ;;
        *) printf '%s' "$1" ;;
    esac
}

SYSCTL="systemctl"
JOURNAL="journalctl"
if [ "$DOCTOR_SCOPE" = "user" ]; then
    SYSCTL="systemctl --user"
    JOURNAL="journalctl --user"
fi

# --- the node directory -----------------------------------------------------
if [ -z "$DOCTOR_DIR" ] && [ -n "$DOCTOR_SERVICE" ]; then
    DOCTOR_DIR=$($SYSCTL show "$DOCTOR_SERVICE" -p WorkingDirectory 2>/dev/null \
        | sed -n 's/^WorkingDirectory=//p' | head -1)
    if [ -z "$DOCTOR_DIR" ] && [ -n "${STELL_NODES:-}" ]; then
        for _n in $STELL_NODES; do
            case "$_n" in
                *[!A-Za-z0-9_]*|'') continue ;;
            esac
            eval "_nsvc=\${NODE_${_n}_SERVICE:-}; _ndir=\${NODE_${_n}_DIR:-}"
            if [ "$_nsvc" = "$DOCTOR_SERVICE" ] && [ -n "$_ndir" ]; then
                DOCTOR_DIR="$_ndir"
                break
            fi
        done
    fi
fi
[ -z "$DOCTOR_DIR" ] && DOCTOR_DIR="$(pwd)"

DATA_DIR="$DOCTOR_DIR/data"
[ -d "$DATA_DIR" ] || DATA_DIR="$DOCTOR_DIR"
STORE_DIR="$DATA_DIR/store"

# --- the env file -----------------------------------------------------------
ENV_FILE=""
if [ -n "$DOCTOR_SERVICE" ]; then
    # `systemctl show -p EnvironmentFiles` outputs:
    #   EnvironmentFiles=/path/to/env (ignore_errors=no)
    ENV_FILE=$($SYSCTL show "$DOCTOR_SERVICE" -p EnvironmentFiles 2>/dev/null \
        | sed -n 's/^EnvironmentFiles=-\{0,1\}\([^ ]*\)\( (ignore_errors=.*\)\{0,1\}$/\1/p' | head -1)
    [ -z "$ENV_FILE" ] && ENV_FILE=$($SYSCTL cat "$DOCTOR_SERVICE" 2>/dev/null \
        | sed -n 's/^EnvironmentFile=-\{0,1\}//p' | head -1 | tr -d '"')
fi
if [ -z "$ENV_FILE" ] && [ -n "${STELL_NODES:-}" ]; then
    for _n in $STELL_NODES; do
        case "$_n" in
            *[!A-Za-z0-9_]*|'') continue ;;
        esac
        eval "_ndir=\${NODE_${_n}_DIR:-}; _nsvc=\${NODE_${_n}_SERVICE:-}; _nenv=\${NODE_${_n}_ENV:-}"
        if { [ -n "$DOCTOR_DIR" ] && [ "$_ndir" = "$DOCTOR_DIR" ]; } \
           || { [ -n "$DOCTOR_SERVICE" ] && [ "$_nsvc" = "$DOCTOR_SERVICE" ]; }; then
            if [ -n "$_nenv" ] && [ -f "$_nenv" ]; then
                ENV_FILE="$_nenv"
                break
            fi
        fi
    done
fi
if [ -z "$ENV_FILE" ]; then
    _base=$(basename "$DOCTOR_DIR")
    _suffix=""
    case "$_base" in
        node?*) _suffix=$(printf '%s' "${_base#node}" | tr 'a-z' 'A-Z') ;;
    esac
    if [ -n "$_suffix" ]; then
        if [ -f "$DOCTOR_DIR/env.$_suffix" ]; then
            ENV_FILE="$DOCTOR_DIR/env.$_suffix"
        elif [ -f "$(dirname "$DOCTOR_DIR")/env.$_suffix" ]; then
            ENV_FILE="$(dirname "$DOCTOR_DIR")/env.$_suffix"
        fi
    fi
fi

env_get() {
    [ -n "$ENV_FILE" ] && [ -r "$ENV_FILE" ] || { echo "<unset>"; return; }
    sed -n "s/^$1=//p" "$ENV_FILE" | tail -1
}

# --- the service ------------------------------------------------------------
svc_state="?"; svc_enabled="?"; svc_restarts="?"; svc_exit="?"; svc_pid="?"
svc_bin="?"; svc_since="?"
if [ -n "$DOCTOR_SERVICE" ]; then
    # `is-active`/`is-enabled` exit non-zero for an inactive/disabled unit, so
    # the "|| echo ?" pattern would capture BOTH outputs. Take the output
    # first, then default.
    svc_state=$($SYSCTL is-active "$DOCTOR_SERVICE" 2>/dev/null || true)
    svc_enabled=$($SYSCTL is-enabled "$DOCTOR_SERVICE" 2>/dev/null || true)
    [ -z "$svc_state" ] && svc_state="?"
    [ -z "$svc_enabled" ] && svc_enabled="?"
    props=$($SYSCTL show "$DOCTOR_SERVICE" -p NRestarts -p ExecMainStatus -p ExecMainPID \
        -p ActiveEnterTimestamp -p ExecStart 2>/dev/null || true)
    svc_restarts=$(printf '%s\n' "$props" | sed -n 's/^NRestarts=//p' | head -1)
    svc_exit=$(printf '%s\n' "$props" | sed -n 's/^ExecMainStatus=//p' | head -1)
    svc_pid=$(printf '%s\n' "$props" | sed -n 's/^ExecMainPID=//p' | head -1)
    svc_since=$(printf '%s\n' "$props" | sed -n 's/^ActiveEnterTimestamp=//p' | head -1)
    svc_bin=$(printf '%s\n' "$props" | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1)
fi

# --- the inodes / disk ------------------------------------------------------
inode_total="?"; inode_used="?"; inode_free="?"; inode_pct="?"
if [ -d "$DATA_DIR" ]; then
    inode_total=$(df -i "$DATA_DIR" 2>/dev/null | awk 'NR==2{print $2}')
    inode_used=$(df -i "$DATA_DIR" 2>/dev/null | awk 'NR==2{print $3}')
    inode_free=$(df -i "$DATA_DIR" 2>/dev/null | awk 'NR==2{print $4}')
    inode_pct=$(df -i "$DATA_DIR" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
fi
disk_pct="?"; data_kb="?"
if [ -d "$DATA_DIR" ]; then
    disk_pct=$(df -P "$DATA_DIR" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
    data_kb=$(du -sk "$DATA_DIR" 2>/dev/null | awk '{print $1}')
fi

# --- the chunk files / orphans ----------------------------------------------
# ONE find pass: the raw list gives the file count (the inode cost), the
# sorted-unique list gives the orphan candidates. The referenced set is every
# chunk id mentioned by any manifest in kv.json — deliberately conservative:
# an expired manifest's chunks count as referenced too, so the sweeper never
# removes a chunk that a manifest (even a dying one) still points at.
chunk_files=0; chunk_orphans=0; chunk_ref=0
if [ -d "$DATA_DIR/chunks" ]; then
    if DOCTOR_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/stell-doctor.XXXXXX" 2>/dev/null); then
        chmod 700 "$DOCTOR_TMPDIR"
        raw="$DOCTOR_TMPDIR/raw"
        have="$DOCTOR_TMPDIR/have"
        find "$DATA_DIR/chunks" -type f ! -name '.*' -printf '%f\n' 2>/dev/null > "$raw"
        chunk_files=$(wc -l < "$raw" | tr -d ' ')
        sort -u "$raw" > "$have" 2>/dev/null || cp "$raw" "$have"
        if [ -r "$DATA_DIR/kv.json" ]; then
            ref="$DOCTOR_TMPDIR/ref"
            # The manifest is a JSON STRING inside kv.json, so its quotes are
            # escaped in the file: \"id\":\"<64 hex>\". Strip the backslashes first,
            # then pull the chunk ids out.
            tr -d '\\' < "$DATA_DIR/kv.json" 2>/dev/null \
                | grep -o '"id"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]\{64\}"' \
                | sed 's/^"id"[[:space:]]*:[[:space:]]*"//; s/"$//' | sort -u > "$ref" 2>/dev/null || : > "$ref"
            chunk_ref=$(wc -l < "$ref" | tr -d ' ')
            chunk_orphans=$(comm -23 "$have" "$ref" 2>/dev/null | wc -l | tr -d ' ')
        fi
        rm -rf "$DOCTOR_TMPDIR"
        DOCTOR_TMPDIR=""
    fi
fi

# --- the consensus checkpoint / genesis root (the store) --------------------
# sled holds an EXCLUSIVE lock on the store while the node runs, so the
# checkpoint is readable only with the node stopped. The tool says so.
cp_height="?"; cp_round="?"; cp_lock_hash="?"; cp_lock_round="?"; cp_final="?"
cp_source="none"; genesis_root="?"; epoch="?"
TOOL=""
[ -x "$STELOPS_BIN" ] && TOOL="$STELOPS_BIN"
[ -x "$STELOPS_REMOTE" ] && TOOL="$STELOPS_REMOTE"

if [ -z "$TOOL" ]; then
    # The tool is what reads the store (checkpoint + genesis root). Without it
    # the checkpoint cannot be read at all.
    cp_source="unavailable(no ops tool: build scripts/tools/stelops and copy it to the node)"
elif [ ! -d "$STORE_DIR" ]; then
    cp_source="no-store"
elif [ -n "$DOCTOR_SERVICE" ] && [ "$svc_state" = "active" ]; then
    # sled holds an EXCLUSIVE lock on the store while the node runs.
    cp_source="unavailable(node running: the store is locked)"
fi

if [ -n "$TOOL" ] && [ -d "$STORE_DIR" ]; then
    out=$("$TOOL" checkpoint "$STORE_DIR" 2>&1)
    if printf '%s' "$out" | grep -q '^height='; then
        cp_height=$(printf '%s' "$out" | sed -n 's/.*height=\([0-9]*\).*/\1/p')
        cp_round=$(printf '%s' "$out" | sed -n 's/.*round=\([0-9]*\).*/\1/p')
        cp_lock_hash=$(printf '%s' "$out" | sed -n 's/.*locked_hash=\([0-9a-f]*\).*/\1/p')
        cp_lock_round=$(printf '%s' "$out" | sed -n 's/.*locked_round=\([0-9]*\).*/\1/p')
        cp_final=$(printf '%s' "$out" | sed -n 's/.*finalized_height=\([0-9]*\).*/\1/p')
        cp_source="store"
    elif [ "$cp_source" = "none" ]; then
        cp_source="unavailable(the store is locked: the node is running)"
    fi
    out=$("$TOOL" genesis-root "$STORE_DIR" 2>&1)
    if printf '%s' "$out" | grep -qE '^[0-9a-f]{64}$'; then
        genesis_root="$out"
        epoch=$(printf '%s' "$out" | cut -c1-16)
    fi
fi

# Fall back to the node's own start-up log line for the lock.
#
# The journals on a busy node hold hundreds of thousands of lines, so the
# search is a server-side `-g` filter (systemd >= 237) with a bounded
# `-n` fallback; the timeout keeps a huge journal from stalling the doctor.
journal_grep() {
    pattern="$1"
    out=$(timeout 10 $JOURNAL -u "$DOCTOR_SERVICE" --no-pager -g "$pattern" 2>/dev/null || true)
    if [ -z "$out" ]; then
        out=$(timeout 10 $JOURNAL -u "$DOCTOR_SERVICE" --no-pager -n 2000 2>/dev/null \
            | grep -E "$pattern" || true)
    fi
    printf '%s' "$out"
}

if [ "$cp_source" != "store" ] && [ -n "$DOCTOR_SERVICE" ] && [ "${DOCTOR_FROM_LOG:-0}" = "1" ]; then
    l=$(journal_grep "restored lock" \
        | grep -oE 'restored lock for height [0-9]+ round [0-9]+' | tail -1)
    if [ -n "$l" ]; then
        cp_height=$(printf '%s' "$l" | awk '{print $4}')
        cp_round=$(printf '%s' "$l" | awk '{print $6}')
        cp_source="log"
    fi
fi

# The chain epoch is ALSO in the node's live subscription state (subs.json) and
# in the blob names in kv.json — both readable while the node runs, unlike the
# store (which sled locks) and unlike the journal (which takes minutes to scan
# on a busy node).
if [ "$epoch" = "?" ] && [ -r "$DATA_DIR/subs.json" ]; then
    e=$(grep -o 'stellereum/consensus/v1/[0-9a-f]\{16\}' "$DATA_DIR/subs.json" 2>/dev/null \
        | head -1 | sed 's|.*/||')
    [ -n "$e" ] && epoch="$e"
fi
if [ "$epoch" = "?" ] && [ -r "$DATA_DIR/kv.json" ]; then
    e=$(grep -o ':[0-9a-f]\{16\}_' "$DATA_DIR/kv.json" 2>/dev/null | head -1 | tr -d ':_')
    [ -n "$e" ] && epoch="$e"
fi

# --- the pubsub topic -------------------------------------------------------
# Derived exactly the way the node derives it:
#   epoch  = hex(genesis_state_root[0..8]);  sharded = |STELL_SHARDS| > 1
#   topic  = stellereum/consensus/v1/<epoch>              (single shard)
#            stellereum/consensus/v1/<epoch>/shard/<id>    (multi shard)
shards=$(env_get STELL_SHARDS)
[ "$shards" = "<unset>" ] && shards="0"
nshards=$(printf '%s' "$shards" | tr ',' '\n' | grep -c '[0-9]')
is_sharded="no"
expected_topic="?"
if [ "$nshards" -gt 1 ] 2>/dev/null; then is_sharded="yes"; fi
if [ "$epoch" != "?" ]; then
    if [ "$is_sharded" = "yes" ]; then
        expected_topic="stellereum/consensus/v1/${epoch}/shard/${DOCTOR_SHARD_ID}"
    else
        expected_topic="stellereum/consensus/v1/${epoch}"
    fi
fi
# A multi-shard process subscribes to ONE topic per shard it runs (shard/0
# AND shard/1), so the subscribed topic is a SET. The node's effective topic
# is the one it SHOULD be on when that one is in the set; otherwise it is
# whatever it actually subscribed to — the isolated case.
subscribed_topics=""
subscribed_topic="?"
# PRIMARY: the node's live subscription state (subs.json) — the topics the
# node is on RIGHT NOW, and the peers on each of them.
if [ -r "$DATA_DIR/subs.json" ]; then
    subscribed_topics=$(grep -o '"stellereum/consensus/v1/[^"]*"' "$DATA_DIR/subs.json" 2>/dev/null \
        | tr -d '"' | sort -u | tr '\n' ',' | sed 's/,$//')
fi
if [ -z "$subscribed_topics" ] && [ -n "$DOCTOR_SERVICE" ]; then
    subscribed_topics=$(journal_grep "subscribing to topic" \
        | grep -oE 'subscribing to topic [^ ]+' | awk '{print $NF}' | sort -u | tr '\n' ',' | sed 's/,$//')
fi
if [ -n "$subscribed_topics" ]; then
    case ",$subscribed_topics," in
        *",$expected_topic,"*) subscribed_topic="$expected_topic" ;;
        *) subscribed_topic=$(printf '%s' "$subscribed_topics" | cut -d, -f1) ;;
    esac
fi
# How many peers are on the node's own consensus topic: zero peers on the
# topic is the fingerprint of an ISOLATED node.
topic_peers="?"
if [ -n "$expected_topic" ] && [ -r "$DATA_DIR/subs.json" ]; then
    block=$(grep -o "\"${expected_topic}\":{[^}]*}" "$DATA_DIR/subs.json" 2>/dev/null | head -1)
    topic_peers=$(printf '%s' "$block" | grep -o 'inf1:[0-9a-f]\{40\}' | sort -u | wc -l | tr -d ' ')
fi

# --- the binary -------------------------------------------------------------
bin_path="$svc_bin"
if [ "$bin_path" = "?" ] || [ -z "$bin_path" ]; then
    if [ -n "$svc_pid" ] && [ "$svc_pid" != "0" ] && [ -r "/proc/$svc_pid/exe" ]; then
        bin_path=$(readlink -f "/proc/$svc_pid/exe" 2>/dev/null || echo "?")
    fi
fi
bin_sha="?"; bin_in_target="no"
if [ -n "$bin_path" ] && [ -x "$bin_path" ]; then
    bin_sha=$(sha256sum "$bin_path" 2>/dev/null | awk '{print $1}')
    case "$bin_path" in
        */target/*) bin_in_target="yes" ;;
    esac
fi

# --- the key format ---------------------------------------------------------
key_format="missing"
if [ -f "$DOCTOR_DIR/keys/identity.key" ]; then
    case "$(head -c 5 "$DOCTOR_DIR/keys/identity.key" 2>/dev/null)" in
        enc2:*) key_format="encrypted" ;;
        enc:*)  key_format="legacy-encrypted" ;;
        *)      key_format="plaintext" ;;
    esac
fi

# --- the RPC ----------------------------------------------------------------
[ -z "$DOCTOR_RPC" ] && DOCTOR_RPC="http://$(env_get STELL_RPC_LISTEN)"
chain_id="?"; base_fee="?"; tip="?"
if [ -n "$DOCTOR_RPC" ] && [ "$DOCTOR_RPC" != "http://<unset>" ]; then
    body=$(curl -s --connect-timeout 3 -m 5 -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":{}}' "$DOCTOR_RPC" 2>/dev/null || true)
    h=$(printf '%s' "$body" | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\(0x[0-9a-fA-F]*\)".*/\1/p')
    [ -n "$h" ] && tip=$(printf '%d' "$h" 2>/dev/null || echo "?")
    body=$(curl -s --connect-timeout 3 -m 5 -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":{}}' "$DOCTOR_RPC" 2>/dev/null || true)
    chain_id=$(printf '%s' "$body" | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
    body=$(curl -s --connect-timeout 3 -m 5 -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"stell_baseFee","params":{}}' "$DOCTOR_RPC" 2>/dev/null || true)
    base_fee=$(printf '%s' "$body" | sed -n 's/.*"base_fee"[[:space:]]*:[[:space:]]*"\([0-9]*\)".*/\1/p')
fi

# --- the drift list ---------------------------------------------------------
# Every difference from the expected cluster config is NAMED.
drift=""
add_drift() { drift="$drift$1
"; }
check_env() {
    name="$1"; expected="$2"; actual=$(env_get "$name")
    [ "$actual" = "$expected" ] && return 0
    add_drift "$name: expected $expected, node has ${actual}"
}
check_env STELL_SHARDS            "$EXPECT_STELL_SHARDS"
check_env STELL_ROUND_TIMEOUT_MS  "$EXPECT_STELL_ROUND_TIMEOUT_MS"
check_env STELL_DOWN_PROPOSER_TIMEOUT_MS "$EXPECT_STELL_DOWN_PROPOSER_TIMEOUT_MS"
check_env STELL_MIN_BLOCK_MS      "$EXPECT_STELL_MIN_BLOCK_MS"
check_env STELL_KEEP_BLOCKS       "$EXPECT_STELL_KEEP_BLOCKS"
check_env STELL_ARCHIVE           "$EXPECT_STELL_ARCHIVE"
if [ "$chain_id" != "?" ] && [ -n "$chain_id" ] && [ "$chain_id" != "$EXPECT_STELL_CHAIN_ID" ]; then
    add_drift "chain id: expected $EXPECT_STELL_CHAIN_ID, node reports $chain_id"
fi
if [ "$base_fee" != "?" ] && [ -n "$base_fee" ] && [ "$base_fee" != "$EXPECT_BASE_FEE" ]; then
    add_drift "admission base fee: expected $EXPECT_BASE_FEE, node reports $base_fee"
fi
if [ -n "$subscribed_topics" ] && [ "$expected_topic" != "?" ]; then
    case ",$subscribed_topics," in
        *",$expected_topic,"*) : ;;
        *) add_drift "pubsub topic: expected $expected_topic, node subscribed to [$subscribed_topics] (ISOLATED FROM THE NETWORK)" ;;
    esac
fi
if [ "$bin_in_target" = "yes" ]; then
    add_drift "the binary runs from a cargo target dir ($bin_path): a 'cargo clean' deletes it under the live node"
fi
if [ -n "$inode_pct" ] && [ "$inode_pct" != "?" ] && [ "$inode_pct" -ge "$INODE_HARD_PCT" ] 2>/dev/null; then
    add_drift "inode usage ${inode_pct}% >= ${INODE_HARD_PCT}%: the filesystem is about to go read-only"
fi
if [ "$chunk_orphans" -ge "$ORPHAN_WARN_COUNT" ] 2>/dev/null; then
    add_drift "$chunk_orphans orphan chunk files: run scripts/node-prune-cron.sh"
fi
if [ -n "$svc_state" ] && [ "$svc_state" != "active" ]; then
    add_drift "the service is '$svc_state', not 'active'"
fi
if [ -n "$svc_enabled" ] && [ "$svc_enabled" != "enabled" ] && [ "$svc_enabled" != "?" ]; then
    add_drift "the service is '$svc_enabled', not 'enabled' — it will NOT come back after a reboot"
fi
if [ -n "$svc_restarts" ] && [ "$svc_restarts" != "?" ] && [ "$svc_restarts" -ge 3 ] 2>/dev/null; then
    add_drift "the service has restarted $svc_restarts times — it is crash-looping"
fi
if [ "$key_format" = "plaintext" ]; then
    add_drift "the node key is stored in PLAINTEXT (set STELL_NODE_PASSPHRASE to encrypt it)"
fi

# --- the report -------------------------------------------------------------
if [ "$DOCTOR_JSON" = "1" ]; then
    drift_line=$(printf '%s' "$drift" | tr '\n' '|')
    printf '{"node_dir":"%s","service":"%s","service_state":"%s","service_enabled":"%s","service_restarts":"%s","service_exit_code":"%s","service_since":"%s","env_file":"%s","inode_total":"%s","inode_used":"%s","inode_free":"%s","inode_pct":"%s","disk_pct":"%s","data_kb":"%s","chunk_files":"%s","chunk_orphans":"%s","chunk_referenced":"%s","checkpoint_height":"%s","checkpoint_round":"%s","lock_hash":"%s","lock_round":"%s","finalized_height":"%s","checkpoint_source":"%s","genesis_root":"%s","epoch":"%s","shards":"%s","is_sharded":"%s","expected_topic":"%s","subscribed_topic":"%s","subscribed_topics":"%s","topic_peers":"%s","binary_path":"%s","binary_sha256":"%s","binary_in_target_dir":"%s","key_format":"%s","chain_id":"%s","base_fee":"%s","tip":"%s","drift":"%s"}\n' \
        "$(json_escape "$DOCTOR_DIR")" \
        "$(json_escape "$DOCTOR_SERVICE")" \
        "$(json_escape "$svc_state")" \
        "$(json_escape "$svc_enabled")" \
        "$(json_escape "$svc_restarts")" \
        "$(json_escape "$svc_exit")" \
        "$(json_escape "$svc_since")" \
        "$(json_escape "$ENV_FILE")" \
        "$(json_escape "$inode_total")" \
        "$(json_escape "$inode_used")" \
        "$(json_escape "$inode_free")" \
        "$(json_escape "$inode_pct")" \
        "$(json_escape "$disk_pct")" \
        "$(json_escape "$data_kb")" \
        "$(json_escape "$chunk_files")" \
        "$(json_escape "$chunk_orphans")" \
        "$(json_escape "$chunk_ref")" \
        "$(json_escape "$cp_height")" \
        "$(json_escape "$cp_round")" \
        "$(json_escape "$cp_lock_hash")" \
        "$(json_escape "$cp_lock_round")" \
        "$(json_escape "$cp_final")" \
        "$(json_escape "$cp_source")" \
        "$(json_escape "$genesis_root")" \
        "$(json_escape "$epoch")" \
        "$(json_escape "$shards")" \
        "$(json_escape "$is_sharded")" \
        "$(json_escape "$expected_topic")" \
        "$(json_escape "$subscribed_topic")" \
        "$(json_escape "$subscribed_topics")" \
        "$(json_escape "$topic_peers")" \
        "$(json_escape "$bin_path")" \
        "$(json_escape "$bin_sha")" \
        "$(json_escape "$bin_in_target")" \
        "$(json_escape "$key_format")" \
        "$(json_escape "$chain_id")" \
        "$(json_escape "$base_fee")" \
        "$(json_escape "$tip")" \
        "$(json_escape "$drift_line")"
    exit 0
fi

if [ "$DOCTOR_QUIET" = "1" ]; then
    [ -n "$drift" ] && printf '%s' "$drift"
    [ -n "$drift" ] && exit 1
    exit 0
fi

echo "================================================================================"
echo " STELLEREUM DOCTOR — $DOCTOR_DIR  ($(date -u '+%Y-%m-%dT%H:%M:%SZ'))"
echo "================================================================================"
echo ""
echo "-- SERVICE ---------------------------------------------------------------"
printf "  %-22s %s\n" "unit" "${DOCTOR_SERVICE:-n/a}"
printf "  %-22s %s\n" "state" "$svc_state"
printf "  %-22s %s\n" "enabled" "$svc_enabled"
printf "  %-22s %s\n" "restarts" "$svc_restarts"
printf "  %-22s %s\n" "last exit code" "$svc_exit"
printf "  %-22s %s\n" "running since" "$svc_since"
echo ""
echo "-- DISK / INODES ---------------------------------------------------------"
printf "  %-22s %s of %s (%s%%)\n" "inodes used" "$inode_used" "$inode_total" "$inode_pct"
printf "  %-22s %s\n" "inodes free" "$inode_free"
printf "  %-22s %s%%\n" "disk used" "$disk_pct"
printf "  %-22s %s KB\n" "data dir size" "$data_kb"
printf "  %-22s %s (%s orphans, %s referenced)\n" "chunk files" "$chunk_files" "$chunk_orphans" "$chunk_ref"
echo ""
echo "-- CONSENSUS CHECKPOINT -------------------------------------------------"
printf "  %-22s %s (source: %s)\n" "height / round" "$cp_height / $cp_round" "$cp_source"
printf "  %-22s %s\n" "locked hash" "$cp_lock_hash"
printf "  %-22s %s\n" "locked round" "$cp_lock_round"
printf "  %-22s %s\n" "finalized height" "$cp_final"
printf "  %-22s %s\n" "genesis root" "$genesis_root"
printf "  %-22s %s\n" "chain epoch" "$epoch"
echo ""
echo "-- PUBSUB TOPIC ---------------------------------------------------------"
printf "  %-22s %s\n" "STELL_SHARDS" "$shards"
printf "  %-22s %s\n" "is_sharded" "$is_sharded"
printf "  %-22s %s\n" "expected topic" "$expected_topic"
printf "  %-22s %s\n" "subscribed topic" "$subscribed_topic"
printf "  %-22s %s\n" "all subscribed topics" "$subscribed_topics"
printf "  %-22s %s\n" "peers on my topic" "$topic_peers"
echo ""
echo "-- BINARY / KEYS / CHAIN ------------------------------------------------"
printf "  %-22s %s\n" "binary" "$bin_path"
printf "  %-22s %s\n" "binary sha256" "$bin_sha"
printf "  %-22s %s\n" "in cargo target dir" "$bin_in_target"
printf "  %-22s %s\n" "key format" "$key_format"
printf "  %-22s %s\n" "chain id" "$chain_id"
printf "  %-22s %s\n" "admission base fee" "$base_fee"
printf "  %-22s %s\n" "masterchain tip" "$tip"
echo ""
echo "-- CONFIG DRIFT ---------------------------------------------------------"
if [ -n "$drift" ]; then
    printf '%s' "$drift" | while IFS= read -r line; do
        [ -n "$line" ] && echo "  ! $line"
    done
    echo ""
    echo "  The node differs from the expected cluster config. A node whose"
    echo "  STELL_SHARDS differs is on a DIFFERENT PUBSUB TOPIC and is isolated"
    echo "  from the network with no log evidence at all."
    exit 1
fi
echo "  none — the config matches the expected cluster values"
exit 0
