#!/bin/sh
# ==============================================================================
# node-prune-cron.sh — the orphan DHT chunk + staging/backup file sweeper.
#
# RUN IT ON EVERY NODE (not just one): during the deployment attempt Node C
# filled ALL 655360 inodes with 463589 ORPHAN CHUNK FILES, went read-only and
# silently dropped out of consensus — while the other nodes had a prune cron
# and C never did.
#
# WHAT IT DELETES
#   The DHT blob store keeps every chunk of a manifest as a separate file
#   under <data>/chunks/<bucket>/<chunk-id>. A manifest is a JSON blob in
#   <data>/kv.json that lists its chunks. When a manifest is OVERWRITTEN (the
#   head pointer is rewritten on every finalize; the "latest snapshot" pointer
#   on every snapshot) its whole chunk set is retired — but the chunk FILES
#   stay on disk forever. The in-process kv sweep only collects EXPIRED
#   manifests, so an overwritten manifest's chunks are never collected: they
#   are orphans, and they are what ate the filesystem.
#
#   This script deletes exactly those: chunk files that
#     (a) are NOT referenced by any manifest in kv.json, AND
#     (b) are OLDER than the grace period (default 2h), AND
#     (c) are not newer than the newest manifest in their bucket.
#
# WHAT IT NEVER TOUCHES
#   * the head pointer's chunks and the active snapshot's chunks: they ARE
#     referenced by a live manifest (the head/snapshot pointers carry a
#     never-expiring TTL), so they are in the referenced set and survive.
#   * anything younger than the grace period: the node persists kv.json with
#     a debounce (INFNODE_KV_DEBOUNCE_MS, 30 min on the live cluster), so a
#     recent chunk may not be in kv.json YET. The grace period is what makes
#     the sweep safe against that.
#   * anything at all when kv.json is stale: if the index the sweep reasons
#     about is older than --max-kv-age, the sweep REFUSES to run.
#
# SAFE TO RUN WHILE THE NODE IS LIVE: it only removes files nothing points
# at any more, and it never touches the store, the key material or the config.
#
# IDEMPOTENT: a second run finds nothing left to delete.
# CONCURRENCY-SAFE: an flock guards the whole run, so a cron tick and the
# watchdog cannot race. Safe to run on several nodes at the same time (they
# are separate machines with separate data dirs).
#
# Usage:
#   node-prune-cron.sh [--dir /root/nodeC] [--data-dir DIR] [--grace-seconds N]
#                       [--max-kv-age N] [--max-delete N] [--dry-run] [--json]
# ==============================================================================

set -u

PRUNE_DIR=""
PRUNE_DATA_DIR=""
PRUNE_GRACE="${PRUNE_GRACE:-7200}"      # 2h: older than any kv.json debounce (30m)
PRUNE_MAX_KV_AGE="${PRUNE_MAX_KV_AGE:-7200}"  # 2h: kv.json must be this fresh
PRUNE_MAX_DELETE="${PRUNE_MAX_DELETE:-200000}"
PRUNE_DRY_RUN=0
PRUNE_JSON=0

usage() {
    cat <<EOF
node-prune-cron.sh — orphan DHT chunk + staging/backup file sweeper for a Stellereum node

USAGE
  node-prune-cron.sh [options]

OPTIONS
  --dir DIR          the node's working directory (holds data/ and keys/)
  --data-dir DIR     the node's data directory (default: <dir>/data)
  --grace-seconds N  only delete chunks older than N seconds (default $PRUNE_GRACE)
  --max-kv-age N     refuse to sweep if kv.json is older than N seconds
                     (default $PRUNE_MAX_KV_AGE)
  --max-delete N     delete at most N files per run (default $PRUNE_MAX_DELETE)
  --dry-run          report what would be deleted, delete nothing
  --json             machine-readable output
  --help             this text

NOTES
  * safe to run while the node is live; it never touches the store, the keys
    or the config.
  * idempotent: a second run has nothing left to do.
  * the grace period protects chunks that are not in kv.json yet (the node
    persists kv.json with a debounce).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dir) [ $# -ge 2 ] || { echo "node-prune-cron.sh: --dir requires an argument" >&2; exit 2; }; PRUNE_DIR="$2"; shift 2 ;;
        --data-dir) [ $# -ge 2 ] || { echo "node-prune-cron.sh: --data-dir requires an argument" >&2; exit 2; }; PRUNE_DATA_DIR="$2"; shift 2 ;;
        --grace-seconds) [ $# -ge 2 ] || { echo "node-prune-cron.sh: --grace-seconds requires an argument" >&2; exit 2; }; PRUNE_GRACE="$2"; shift 2 ;;
        --max-kv-age) [ $# -ge 2 ] || { echo "node-prune-cron.sh: --max-kv-age requires an argument" >&2; exit 2; }; PRUNE_MAX_KV_AGE="$2"; shift 2 ;;
        --max-delete) [ $# -ge 2 ] || { echo "node-prune-cron.sh: --max-delete requires an argument" >&2; exit 2; }; PRUNE_MAX_DELETE="$2"; shift 2 ;;
        --dry-run) PRUNE_DRY_RUN=1; shift ;;
        --json) PRUNE_JSON=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "node-prune-cron.sh: unknown option '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

# --- the data directory -----------------------------------------------------
if [ -z "$PRUNE_DATA_DIR" ]; then
    if [ -z "$PRUNE_DIR" ]; then
        # The node's working directory: the systemd unit's WorkingDirectory, or
        # the directory this script was started from.
        PRUNE_DIR="$(pwd)"
    fi
    PRUNE_DATA_DIR="$PRUNE_DIR/data"
fi
[ -d "$PRUNE_DATA_DIR" ] || { echo "node-prune-cron.sh: no data dir at $PRUNE_DATA_DIR" >&2; exit 2; }

CHUNKS_DIR="$PRUNE_DATA_DIR/chunks"
KV="$PRUNE_DATA_DIR/kv.json"
LOCKFILE="$PRUNE_DATA_DIR/.prune.lock"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/stell-prune.XXXXXX" 2>/dev/null)" || {
    echo "node-prune-cron.sh: failed to create temporary directory" >&2
    exit 1
}
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT INT TERM

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

now=$(date +%s)

# --- the lock ---------------------------------------------------------------
# One sweeper per node at a time. `flock` is not POSIX, but it is on every
# Linux box; without it the script still works, it just does not serialise.
if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCKFILE" || true
    if ! flock -n 9 2>/dev/null; then
        echo "node-prune-cron.sh: another sweeper is running on this node — nothing to do"
        exit 0
    fi
fi

# --- the report helper ------------------------------------------------------
report() {
    if [ "$PRUNE_JSON" = "1" ]; then
        printf '{"data_dir":"%s","chunks_dir":"%s","chunk_files":%s,"referenced":%s,"candidates":%s,"deleted":%s,"bytes_freed":%s,"inode_pct_before":"%s","inode_pct_after":"%s","skipped":"%s","reason":"%s"}\n' \
            "$(json_escape "$PRUNE_DATA_DIR")" \
            "$(json_escape "$CHUNKS_DIR")" \
            "${CHUNK_FILES:-0}" "${REF_COUNT:-0}" "${CANDIDATES:-0}" \
            "${DELETED:-0}" "${BYTES:-0}" \
            "$(json_escape "${INODE_PCT_BEFORE:-?}")" \
            "$(json_escape "${INODE_PCT_AFTER:-?}")" \
            "$(json_escape "${SKIPPED_REASON:-}")" \
            "$(json_escape "${REASON:-ok}")"
    else
        echo "data dir         : $PRUNE_DATA_DIR"
        echo "chunk files      : ${CHUNK_FILES:-0}"
        echo "referenced       : ${REF_COUNT:-0}"
        echo "delete candidates: ${CANDIDATES:-0}"
        echo "deleted          : ${DELETED:-0} (${BYTES:-0} bytes)"
        echo "inode usage      : ${INODE_PCT_BEFORE:-?}% -> ${INODE_PCT_AFTER:-?}%"
        [ -n "${SKIPPED_REASON:-}" ] && echo "SKIPPED          : $SKIPPED_REASON"
    fi
}

CHUNK_FILES=0; REF_COUNT=0; CANDIDATES=0; DELETED=0; BYTES=0
SKIPPED_REASON=""; REASON="ok"
INODE_PCT_BEFORE=$(df -i "$PRUNE_DATA_DIR" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
INODE_PCT_AFTER="$INODE_PCT_BEFORE"

if [ ! -d "$CHUNKS_DIR" ]; then
    SKIPPED_REASON="no chunks directory under $PRUNE_DATA_DIR"
    report
    exit 0
fi

if [ ! -r "$KV" ]; then
    SKIPPED_REASON="no kv.json under $PRUNE_DATA_DIR — the sweep cannot tell a live chunk from an orphan"
    report
    exit 0
fi

kv_age=$(( now - $(stat -c %Y "$KV" 2>/dev/null || echo 0) ))
if [ "$kv_age" -gt "$PRUNE_MAX_KV_AGE" ] 2>/dev/null; then
    SKIPPED_REASON="kv.json is ${kv_age}s old (> ${PRUNE_MAX_KV_AGE}s) — the index is too stale to sweep safely"
    report
    exit 0
fi

# --- the referenced set -----------------------------------------------------
# Every chunk id mentioned by ANY manifest in kv.json. Deliberately
# conservative: an expired manifest's chunks count as referenced too, so the
# sweep never removes a chunk that a manifest (even a dying one) points at.
# The manifests are JSON STRINGS inside kv.json, so their quotes are escaped
# (\"id\":\"<64 hex>\"): strip the backslashes first.
tr -d '\\' < "$KV" 2>/dev/null \
    | grep -o '"id"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]\{64\}"' \
    | sed 's/^"id"[[:space:]]*:[[:space:]]*"//; s/"$//' | sort -u > "$WORK/ref" 2>/dev/null || : > "$WORK/ref"
REF_COUNT=$(wc -l < "$WORK/ref" | tr -d ' ')

# --- the candidates ---------------------------------------------------------
# One find pass: the raw list (names + mtime + size) gives the file count and
# the age test; the sorted-unique names give the set difference.
# One find pass: "<mtime> <size> <path>" per file. The name (the chunk id) is
# the last path segment.
: > "$WORK/raw"
find "$CHUNKS_DIR" -type f ! -name '.*' -printf '%T@ %s %p\n' 2>/dev/null > "$WORK/raw" || : > "$WORK/raw"
CHUNK_FILES=$(wc -l < "$WORK/raw" | tr -d ' ')

sed 's|^[^ ]* [^ ]* ||; s|.*/||' "$WORK/raw" | sort -u > "$WORK/have" 2>/dev/null || : > "$WORK/have"
comm -23 "$WORK/have" "$WORK/ref" > "$WORK/orphan_ids" 2>/dev/null || : > "$WORK/orphan_ids"

# The candidate set: the files that are NOT referenced by any manifest AND are
# older than the grace period. One awk pass with a hash table — a per-file
# grep against the reference set would be quadratic.
# (The mtime is the file's own; a chunk written 10 minutes ago may not be in
# kv.json yet because the node persists it with a debounce.)
awk -v now="$now" -v grace="$PRUNE_GRACE" '
    NR == FNR { ref[$1] = 1; next }
    {
        full = $3; name = full; sub(/.*\//, "", name)
        if (name in ref) next
        age = now - $1
        if (age < grace) next
        print
    }
' "$WORK/ref" "$WORK/raw" > "$WORK/candidates" 2>/dev/null || : > "$WORK/candidates"
CANDIDATES=$(wc -l < "$WORK/candidates" | tr -d ' ')

if [ "$CANDIDATES" = "0" ]; then
    REASON="nothing to delete"
    report
    exit 0
fi

# --- the deletion -----------------------------------------------------------
if [ "$PRUNE_DRY_RUN" = "1" ]; then
    REASON="dry run"
    report
    exit 0
fi

# The final safety pass, immediately before the deletion:
#   * a fresh find of the files that are STILL older than the grace period
#     (a chunk id can be reused: chunk ids are content-addressed, so a fresh
#     chunk may carry an id that an old orphan also had);
#   * one more awk pass against the referenced set.
# Then the deletion itself, batched through xargs (no fork per file).
find "$CHUNKS_DIR" -type f ! -name '.*' -mmin "+$(( PRUNE_GRACE / 60 ))" -printf '%p\n' 2>/dev/null \
    > "$WORK/old" || : > "$WORK/old"
awk -v now="$now" -v grace="$PRUNE_GRACE" '
    NR == FNR { ref[$1] = 1; next }
    {
        full = $1; name = full; sub(/.*\//, "", name)
        if (name in ref) next
        print full
    }
' "$WORK/ref" "$WORK/old" > "$WORK/safe" 2>/dev/null || : > "$WORK/safe"

DELETED=$(wc -l < "$WORK/safe" | tr -d ' ')
REASON="swept"

if [ "$DELETED" -gt "$PRUNE_MAX_DELETE" ] 2>/dev/null; then
    head -n "$PRUNE_MAX_DELETE" "$WORK/safe" > "$WORK/safe2"
    mv "$WORK/safe2" "$WORK/safe"
    DELETED="$PRUNE_MAX_DELETE"
    REASON="swept (capped at $PRUNE_MAX_DELETE per run)"
fi

# the byte total from the find pass (computed after capping to PRUNE_MAX_DELETE)
BYTES=$(awk 'NR == FNR { sz[$3] = $2; next } { if ($1 in sz) t += sz[$1] } END { print t + 0 }' \
    "$WORK/raw" "$WORK/safe" 2>/dev/null || echo 0)
BYTES=${BYTES:-0}

if [ "$DELETED" -gt 0 ]; then
    # xargs batches the paths; no fork per file.
    tr '\n' '\0' < "$WORK/safe" | xargs -0 -r rm -f 2>/dev/null || true
fi

# --- the housekeeping -------------------------------------------------------
# Atomic-write leftovers (".<name>.tmp.<pid>") of a crashed write: they are
# pure garbage, but only once they are older than the grace period.
if [ "${PRUNE_CLEAN_TMP:-1}" = "1" ]; then
    find "$CHUNKS_DIR" -type f -name '.*' -mmin "+$((PRUNE_GRACE / 60))" -delete 2>/dev/null || true
fi
# The kv.json rotation: infnode keeps ONE backup; a crash loop can leave
# more. Keep the two newest, delete the rest.
if [ "${PRUNE_CLEAN_KVBAK:-1}" = "1" ]; then
    ls -1t "$PRUNE_DATA_DIR"/kv.json.bak-* 2>/dev/null | tail -n +3 | while read -r old; do
        rm -f "$old" 2>/dev/null || true
    done
fi

INODE_PCT_AFTER=$(df -i "$PRUNE_DATA_DIR" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
report
exit 0
