#!/bin/sh
# ==============================================================================
# nodeprobe.sh — collect ONE node's operational state as `key=value` lines.
#
# This file is not meant to be executed directly. It is PIPE-STDIN to a shell
# on the node itself, so the same code runs for a local node and for a remote
# one:
#
#   ssh host "STELL_PROBE_NODE=C ... sh -s" < nodeprobe.sh
#   sh -s < nodeprobe.sh        (locally, with the same env vars)
#
# Parameters (all optional, all via the environment):
#   STELL_PROBE_NODE        node label (A/B/C/D)
#   STELL_PROBE_DIR         the node's working directory (holds data/, keys/)
#   STELL_PROBE_SERVICE     the systemd unit name
#   STELL_PROBE_SERVICE_SCOPE  "system" (default) or "user"
#   STELL_PROBE_RPC         the node's RPC URL (127.0.0.1:PORT)
#   STELL_PROBE_BINARY      the expected binary path (may be empty)
#   STELL_PROBE_SHARD_ID    the shard the node validates (default 1)
#   STELL_PROBE_ORPHANS     1 = count orphan chunk files (slow on a big store)
#   STELL_PROBE_ENV_FILE    the env file to read (default: from the unit)
#
# Output: one `key=value` per line. A value NEVER contains a newline. A key
# that could not be determined is emitted as `key=?`.
#
# POSIX sh only. No bashisms. No writes. Read-only by construction.
# ==============================================================================

emit() { printf '%s=%s\n' "$1" "$2"; }

# --- 0. parameters ----------------------------------------------------------
NODE="${STELL_PROBE_NODE:-?}"
DIR="${STELL_PROBE_DIR:-}"
SERVICE="${STELL_PROBE_SERVICE:-}"
SCOPE="${STELL_PROBE_SERVICE_SCOPE:-system}"
RPC="${STELL_PROBE_RPC:-}"
BIN_HINT="${STELL_PROBE_BINARY:-}"
SHARD_ID="${STELL_PROBE_SHARD_ID:-1}"
ORPHANS="${STELL_PROBE_ORPHANS:-1}"
ENV_FILE="${STELL_PROBE_ENV_FILE:-}"

emit node "$NODE"

if [ "$SCOPE" = "user" ]; then
    SYSCTL="systemctl --user"
    JOURNAL="journalctl --user"
else
    SYSCTL="systemctl"
    JOURNAL="journalctl"
fi

# --- 1. service state -------------------------------------------------------
svc_state="?"
svc_enabled="?"
svc_restarts="?"
svc_exit="?"
svc_pid="?"
svc_since="?"
svc_bin="?"

if [ -n "$SERVICE" ]; then
    # `is-active`/`is-enabled` exit non-zero for an inactive/disabled unit, so
    # the "|| echo ?" pattern would capture BOTH outputs. Take the output first,
    # then default.
    svc_state=$($SYSCTL is-active "$SERVICE" 2>/dev/null || true)
    svc_enabled=$($SYSCTL is-enabled "$SERVICE" 2>/dev/null || true)
    [ -z "$svc_state" ] && svc_state="?"
    [ -z "$svc_enabled" ] && svc_enabled="?"
    props=$($SYSCTL show "$SERVICE" -p NRestarts -p ExecMainStatus -p ExecMainPID \
        -p ActiveEnterTimestamp -p ExecStart 2>/dev/null || true)
    svc_restarts=$(printf '%s\n' "$props" | sed -n 's/^NRestarts=//p' | head -1)
    svc_exit=$(printf '%s\n' "$props" | sed -n 's/^ExecMainStatus=//p' | head -1)
    svc_pid=$(printf '%s\n' "$props" | sed -n 's/^ExecMainPID=//p' | head -1)
    svc_since=$(printf '%s\n' "$props" | sed -n 's/^ActiveEnterTimestamp=//p' | head -1)
    # ExecStart looks like: { path=/x/y ; argv[]=/x/y run --config ... ; ... }
    svc_bin=$(printf '%s\n' "$props" | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -1)
fi
emit service "$SERVICE"
emit service_state "$svc_state"
emit service_enabled "$svc_enabled"
emit service_restarts "${svc_restarts:-?}"
emit service_exit_code "${svc_exit:-?}"
emit service_pid "${svc_pid:-?}"
emit service_since "${svc_since:-?}"

# Crash-looping = systemd restarted it several times in a short window.
# NRestarts is cumulative for the unit's life, so it is only a hint; the
# watchdog also looks at the journal for the "start request repeated too
# quickly" / 203/EXEC signature.
emit service_exec_start "${svc_bin:-?}"

# --- 2. working directory / env file ---------------------------------------
if [ -z "$DIR" ] && [ -n "$svc_bin" ]; then
    DIR=""
fi
emit node_dir "${DIR:-?}"

if [ -z "$ENV_FILE" ] && [ -n "$SERVICE" ]; then
    ENV_FILE=$($SYSCTL show "$SERVICE" -p EnvironmentFiles 2>/dev/null \
        | sed -n 's/.*(ignore_errors=[a-z]*)\{0,1\} *\([^ ]*\) (.*/\1/p' | head -1)
    [ -z "$ENV_FILE" ] && ENV_FILE=$($SYSCTL cat "$SERVICE" 2>/dev/null \
        | sed -n 's/^EnvironmentFile=//p' | head -1 | tr -d '"')
fi
emit env_file "${ENV_FILE:-?}"

# The consensus-critical env values. These are the ones that MUST be identical
# on every node of a cluster; a difference is a network split waiting to
# happen (see the incident: STELL_SHARDS=0 on one node put it on a different
# pubsub topic, with no log evidence at all).
for v in STELL_SHARDS STELL_ROUND_TIMEOUT_MS STELL_DOWN_PROPOSER_TIMEOUT_MS \
         STELL_MIN_BLOCK_MS STELL_KEEP_BLOCKS STELL_ARCHIVE STELL_CHAIN_ID \
         STELL_MIN_GAS_LIMIT STELL_TICK_MS STELL_BROADCAST_JOIN_MS \
         STELL_DHT_KEEP_BLOCKS_DEFAULT STELL_DHT_PRUNE_INTERVAL_HEIGHTS \
         STELL_DHT_PRUNE_MAX_PER_RUN STELL_DHT_FOREVER_TTL_MS \
         STELL_PARALLEL_EXEC STELL_PURE_PQ STELL_LEGACY_GENESIS_ROOT \
         INFNODE_KV_DEBOUNCE_MS STELL_RPC_LISTEN STELL_EXPLORER_LISTEN
do
    val=""
    if [ -n "$ENV_FILE" ] && [ -r "$ENV_FILE" ]; then
        val=$(sed -n "s/^${v}=//p" "$ENV_FILE" | tail -1)
    fi
    emit "env_$v" "${val:-<unset>}"
done

# --- 3. data dir: inodes, chunks, orphans ----------------------------------
DATA_DIR=""
if [ -n "$DIR" ] && [ -d "$DIR/data" ]; then
    DATA_DIR="$DIR/data"
elif [ -n "$DIR" ] && [ -d "$DIR" ]; then
    DATA_DIR="$DIR"
fi
emit data_dir "${DATA_DIR:-?}"

if [ -n "$DATA_DIR" ] && [ -d "$DATA_DIR" ]; then
    # --- inode usage on the filesystem that holds the data dir
    in_total=$(df -i "$DATA_DIR" 2>/dev/null | awk 'NR==2{print $2}')
    in_used=$(df -i "$DATA_DIR" 2>/dev/null | awk 'NR==2{print $3}')
    in_free=$(df -i "$DATA_DIR" 2>/dev/null | awk 'NR==2{print $4}')
    in_pct=$(df -i "$DATA_DIR" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
    emit inode_total "${in_total:-?}"
    emit inode_used "${in_used:-?}"
    emit inode_free "${in_free:-?}"
    emit inode_pct "${in_pct:-?}"
    # --- byte usage
    emit disk_pct "$(df -P "$DATA_DIR" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')"
    emit disk_used_kb "$(du -sk "$DATA_DIR" 2>/dev/null | awk '{print $1}')"

    # --- chunk files (the DHT blob store: <data>/chunks/<bucket>/<id>)
    if [ -d "$DATA_DIR/chunks" ]; then
        # ONE find pass: the raw list gives the file count (the inode cost),
        # the sorted-unique list gives the orphan candidates.
        find "$DATA_DIR/chunks" -type f ! -name '.*' -printf '%f\n' 2>/dev/null > /tmp/.stel-raw.$$ 2>/dev/null || : > /tmp/.stel-raw.$$
        chunk_files=$(wc -l < /tmp/.stel-raw.$$ | tr -d ' ')
        chunk_hidden=$(find "$DATA_DIR/chunks" -type f -name '.*' 2>/dev/null | wc -l | tr -d ' ')
        emit chunk_files "${chunk_files:-0}"
        emit chunk_hidden_files "${chunk_hidden:-0}"
        if [ "$ORPHANS" = "1" ]; then
            # The referenced set = every chunk id mentioned by any manifest in
            # kv.json. Deliberately CONSERVATIVE: an expired manifest's chunks
            # count as referenced too, so the sweeper never removes a chunk a
            # manifest (even a dying one) still points at.
            if [ -r "$DATA_DIR/kv.json" ]; then
                sort -u /tmp/.stel-raw.$$ > /tmp/.stel-have.$$ 2>/dev/null || cp /tmp/.stel-raw.$$ /tmp/.stel-have.$$
                # The manifest is a JSON STRING inside kv.json: its quotes are
                # escaped (\"id\":\"<64 hex>\"). Strip the backslashes first.
                tr -d '\\' < "$DATA_DIR/kv.json" 2>/dev/null \
                    | grep -o '"id"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]\{64\}"' \
                    | sed 's/^"id"[[:space:]]*:[[:space:]]*"//; s/"$//' | sort -u > /tmp/.stel-ref.$$ 2>/dev/null || : > /tmp/.stel-ref.$$
                chunk_ref=$(wc -l < /tmp/.stel-ref.$$ | tr -d ' ')
                chunk_orph=$(comm -23 /tmp/.stel-have.$$ /tmp/.stel-ref.$$ 2>/dev/null | wc -l | tr -d ' ')
                rm -f /tmp/.stel-ref.$$ /tmp/.stel-have.$$
                emit chunk_referenced "${chunk_ref:-0}"
                emit chunk_orphans "${chunk_orph:-0}"
            else
                emit chunk_referenced "?"
                emit chunk_orphans "?"
            fi
        else
            emit chunk_referenced "skipped"
            emit chunk_orphans "skipped"
        fi
        rm -f /tmp/.stel-raw.$$
    else
        emit chunk_files "0"
        emit chunk_hidden_files "0"
        emit chunk_referenced "0"
        emit chunk_orphans "0"
    fi

    # --- kv.json freshness: the sweeper refuses to run on a stale index
    if [ -r "$DATA_DIR/kv.json" ]; then
        kv_age=$(( $(date +%s) - $(stat -c %Y "$DATA_DIR/kv.json" 2>/dev/null || echo 0) ))
        emit kv_json_age_s "${kv_age:-?}"
    else
        emit kv_json_age_s "?"
    fi
else
    emit inode_total "?"
    emit inode_used "?"
    emit inode_free "?"
    emit inode_pct "?"
    emit disk_pct "?"
    emit disk_used_kb "?"
    emit chunk_files "0"
    emit chunk_hidden_files "0"
    emit chunk_referenced "0"
    emit chunk_orphans "0"
    emit kv_json_age_s "?"
fi

# --- 4. the binary: path + hash --------------------------------------------
bin_path="${svc_bin}"
if [ -z "$bin_path" ] && [ -n "$BIN_HINT" ]; then
    bin_path="$BIN_HINT"
fi
if [ -z "$bin_path" ] && [ -n "$svc_pid" ] && [ "$svc_pid" != "0" ] && [ -r "/proc/$svc_pid/exe" ]; then
    bin_path=$(readlink -f "/proc/$svc_pid/exe" 2>/dev/null || true)
fi
emit binary_path "${bin_path:-?}"
if [ -n "$bin_path" ] && [ -x "$bin_path" ]; then
    emit binary_sha256 "$(sha256sum "$bin_path" 2>/dev/null | awk '{print $1}')"
    emit binary_size "$(stat -c %s "$bin_path" 2>/dev/null || echo '?')"
    emit binary_mtime "$(stat -c %Y "$bin_path" 2>/dev/null || echo '?')"
else
    emit binary_sha256 "?"
    emit binary_size "?"
    emit binary_mtime "?"
fi
# A binary INSIDE a cargo target dir is a live hazard: `cargo clean` deletes
# it under the running node and the unit crash-loops on 203/EXEC.
case "$bin_path" in
    */target/release/*|*/target/debug/*|*/target/*)
        emit binary_in_target_dir "yes" ;;
    *)  emit binary_in_target_dir "no" ;;
esac

# --- 5. the pubsub topic, exactly as the node derives it -------------------
# The node logs both the chain epoch and the topic it subscribes to. The log
# is the ground truth ("derived the same way the node derives it"); the
# expected topic is recomputed from the epoch + the shard set below.
#
# ONE journal pass for both (the journals on a busy node hold hundreds of
# thousands of lines; three separate scans would cost minutes). `-g` is a
# server-side message filter (systemd >= 237); the bounded `-n` fallback is
# for older systemd. The timeout keeps a huge journal from stalling the probe.
epoch="?"
topic="?"
topics=""
subscribed_last=""
topic_peers="?"

# The PRIMARY source is the node's own live subscription state (subs.json):
# it lists the topics the node is on, RIGHT NOW, and is written continuously.
# It is far cheaper and far more current than grepping the journal.
if [ -n "$DATA_DIR" ] && [ -r "$DATA_DIR/subs.json" ]; then
    topics=$(grep -o '"stellereum/consensus/v1/[^"]*"' "$DATA_DIR/subs.json" 2>/dev/null \
        | tr -d '"' | sort -u | tr '\n' ',' | sed 's/,$//')
    epoch=$(grep -o 'stellereum/consensus/v1/[0-9a-f]\{16\}' "$DATA_DIR/subs.json" 2>/dev/null \
        | head -1 | sed 's|.*/||')
fi
if [ -z "$epoch" ] && [ -n "$DATA_DIR" ] && [ -r "$DATA_DIR/kv.json" ]; then
    # The blob names carry the epoch: "stell_headers:<epoch>_h_<height>".
    epoch=$(grep -o ':[0-9a-f]\{16\}_' "$DATA_DIR/kv.json" 2>/dev/null | head -1 | tr -d ':_')
fi
# The journal is only a FALLBACK: on a busy node the journal holds hundreds of
# thousands of lines and even a server-side `-g` filter takes minutes. The
# live sources (subs.json, kv.json) answer the same questions in
# milliseconds, so the journal is touched only when they are missing.
if [ -n "$SERVICE" ] && { [ -z "$epoch" ] || [ -z "$topics" ]; }; then
    jlines=$(timeout 10 $JOURNAL -u "$SERVICE" --no-pager -g "chain epoch|subscribing to topic" 2>/dev/null \
        | tail -40 || true)
    if [ -z "$jlines" ]; then
        jlines=$(timeout 10 $JOURNAL -u "$SERVICE" --no-pager -n 2000 2>/dev/null \
            | grep -E "chain epoch|subscribing to topic" | tail -40 || true)
    fi
    [ -z "$epoch" ] && epoch=$(printf '%s\n' "$jlines" | grep -oE 'chain epoch [0-9a-f]{16}' | tail -1 | awk '{print $3}')
    if [ -z "$topics" ]; then
        # A multi-shard process subscribes to ONE topic per shard it runs
        # (shard/0 AND shard/1), so the topic is a SET, not a single string.
        topics=$(printf '%s\n' "$jlines" | grep -oE 'subscribing to topic [^ ]+' | awk '{print $NF}' | sort -u | tr '\n' ',' | sed 's/,$//')
    fi
    subscribed_last=$(printf '%s\n' "$jlines" | grep -oE 'subscribing to topic [^ ]+' | tail -1 | awk '{print $NF}')
fi

# The topic the node SHOULD be on, recomputed the way the node does it:
#   epoch  = hex(genesis_root[0..8])
#   sharded = the shard set has more than one id
#   topic  = .../<epoch>            when not sharded
#            .../<epoch>/shard/<id>  when sharded
expect_topic="?"
if [ "$epoch" != "?" ] && [ -n "$ENV_FILE" ] && [ -r "$ENV_FILE" ]; then
    shards=$(sed -n 's/^STELL_SHARDS=//p' "$ENV_FILE" | tail -1)
    [ -z "$shards" ] && shards="0"
    nshards=$(printf '%s' "$shards" | tr ',' '\n' | grep -c '[0-9]')
    if [ "$nshards" -gt 1 ] 2>/dev/null; then
        expect_topic="stellereum/consensus/v1/${epoch}/shard/${SHARD_ID}"
        emit is_sharded "yes"
    else
        expect_topic="stellereum/consensus/v1/${epoch}"
        emit is_sharded "no"
    fi
    emit expected_topic "$expect_topic"
    emit expected_shards "$shards"
else
    emit is_sharded "?"
    emit expected_topic "?"
    emit expected_shards "?"
fi

# The node's EFFECTIVE topic: the one it should be on, when it is among the
# topics it actually subscribed to. When it is not, the effective topic is
# whatever it did subscribe to — that is the isolated case.
if [ "$expect_topic" != "?" ]; then
    case ",$topics," in
        *",$expect_topic,"*) topic="$expect_topic" ;;
        *)                  topic="$subscribed_last" ;;
    esac
else
    topic="$subscribed_last"
fi
[ -z "$topic" ] && topic="?"
emit epoch "${epoch:-?}"
emit topic "${topic:-?}"
emit topics "${topics:-?}"
# How many peers are on the node's own consensus topic right now. Zero peers
# on the topic is the fingerprint of an ISOLATED node.
if [ -n "$expect_topic" ] && [ -n "$DATA_DIR" ] && [ -r "$DATA_DIR/subs.json" ]; then
    block=$(grep -o "\"${expect_topic}\":{[^}]*}" "$DATA_DIR/subs.json" 2>/dev/null | head -1)
    topic_peers=$(printf '%s' "$block" | grep -o 'inf1:[0-9a-f]\{40\}' | sort -u | wc -l | tr -d ' ')
fi
emit topic_peers "${topic_peers:-?}"
# NOTE: `case` is used instead of `[ ... != *pat* ]`: in dash a quoted part of
# the pattern makes the WHOLE operand literal, so the test would always say
# "different".
mismatch="no"
if [ "$expect_topic" != "?" ] && [ -n "$topics" ]; then
    case ",$topics," in
        *",$expect_topic,"*) mismatch="no" ;;
        *)                  mismatch="yes" ;;
    esac
fi
emit topic_mismatch "$mismatch"

# --- 6. the consensus lock --------------------------------------------------
# Two sources: the persisted checkpoint in the store (only readable when the
# node is STOPPED — sled holds an exclusive lock) and the node's own start-up
# log line ("restored lock for height H round R").
lock_h="?"
lock_r="?"
lock_hash="?"
lock_src="unavailable"

# The persisted lock lives in the store, and sled holds an EXCLUSIVE lock on
# the store while the node runs: the checkpoint is readable only with the
# node STOPPED. When the node is up, the lock is in memory and there is
# nothing on disk to read — that is reported honestly, not guessed.
if [ -z "$DATA_DIR" ] || [ ! -d "$DATA_DIR/store" ]; then
    lock_src="no-store"
else
    tool=""
    [ -x "$STELOPS_REMOTE" ] && tool="$STELOPS_REMOTE"
    [ -x "$STELOPS_BIN" ] && tool="$STELOPS_BIN"
    if [ -n "$tool" ]; then
        cp=$("$tool" checkpoint "$DATA_DIR/store" 2>/dev/null || true)
        if printf '%s' "$cp" | grep -q '^height='; then
            lock_h=$(printf '%s' "$cp" | sed -n 's/.*height=\([0-9]*\).*/\1/p')
            lock_r=$(printf '%s' "$cp" | sed -n 's/.*round=\([0-9]*\).*/\1/p')
            lock_hash=$(printf '%s' "$cp" | sed -n 's/.*locked_hash=\([0-9a-f]*\).*/\1/p')
            lock_src="store"
        else
            lock_src="unavailable(store locked: the node is running)"
        fi
    else
        lock_src="unavailable(no ops tool)"
    fi
fi

# The start-up log line is the fallback, and it is opt-in: on a busy node the
# journal scan takes minutes.
if [ "${STELL_PROBE_LOCK_LOG:-0}" = "1" ] && [ -n "$SERVICE" ]; then
    l=$(timeout 15 $JOURNAL -u "$SERVICE" --no-pager -g "restored lock" 2>/dev/null \
        | grep -oE 'restored lock for height [0-9]+ round [0-9]+' | tail -1 || true)
    if [ -n "$l" ]; then
        lock_h=$(printf '%s' "$l" | awk '{print $4}')
        lock_r=$(printf '%s' "$l" | awk '{print $6}')
        lock_src="log"
    fi
fi
emit lock_height "$lock_h"
emit lock_round "$lock_r"
emit lock_hash "$lock_hash"
emit lock_source "$lock_src"

# --- 7. the node's key material format -------------------------------------
key_format="missing"
if [ -n "$DIR" ] && [ -d "$DIR/keys" ]; then
    kf=$(head -c 5 "$DIR/keys/identity.key" 2>/dev/null || true)
    case "$kf" in
        enc2:*) key_format="encrypted" ;;
        enc:*)  key_format="legacy-encrypted" ;;
        "")     key_format="empty" ;;
        *)      key_format="plaintext" ;;
    esac
    emit key_files "$(ls -1 "$DIR/keys" 2>/dev/null | tr '\n' ',')"
    # The node id: the validator identity that goes into the validator set.
    nid=$(grep -oE 'inf1:[0-9a-f]{40}' "$DIR/node.yaml" 2>/dev/null | head -1)
    emit node_yaml_validator "$(grep -A3 '^validators:' "$DIR/node.yaml" 2>/dev/null | grep -oE 'inf1:[0-9a-f]{40}' | tr '\n' ',')"
    emit node_yaml_validators "$(grep -A8 '^validators:' "$DIR/node.yaml" 2>/dev/null | grep -oE 'inf1:[0-9a-f]{40}' | tr '\n' ',')"
fi
emit key_format "$key_format"

# --- 8. the live RPC --------------------------------------------------------
rpc_ok="no"
tip="?"
chain_id="?"
base_fee="?"
if [ -n "$RPC" ]; then
    body=$(curl -s --connect-timeout 3 -m 5 -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":{}}' "$RPC" 2>/dev/null || true)
    h=$(printf '%s' "$body" | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*"\(0x[0-9a-fA-F]*\)".*/\1/p')
    if [ -n "$h" ]; then
        rpc_ok="yes"
        tip=$(printf '%d' "$h" 2>/dev/null || echo "?")
    fi
    cbody=$(curl -s --connect-timeout 3 -m 5 -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":{}}' "$RPC" 2>/dev/null || true)
    chain_id=$(printf '%s' "$cbody" | sed -n 's/.*"result"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
    bbody=$(curl -s --connect-timeout 3 -m 5 -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"stell_baseFee","params":{}}' "$RPC" 2>/dev/null || true)
    base_fee=$(printf '%s' "$bbody" | sed -n 's/.*"base_fee"[[:space:]]*:[[:space:]]*"\([0-9]*\)".*/\1/p')
fi
emit rpc "$rpc_ok"
emit tip "${tip:-?}"
emit chain_id "${chain_id:-?}"
emit base_fee "${base_fee:-?}"

exit 0
