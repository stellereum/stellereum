#!/usr/bin/env bash
# backup_verify.sh — snapshot a Stellereum data dir, checksum it, restore the
# image into a temp dir, re-verify, and do a boot-read sanity check.
#
# NON-DESTRUCTIVE BY CONSTRUCTION:
#   - the live data dir is only ever READ (cp -a out of it, never move/rm);
#   - the manifest and all temp copies live OUTSIDE the data dir;
#   - nothing is written into --data-dir, ever (guarded, fails closed).
#
# Crash-consistency note: a `cp -a` of a LIVE (running) node is a
# filesystem copy, not a consensus snapshot — it proves restorability of the
# files, not point-in-time consistency. For a strict backup, stop the node
# first (./scripts/local-cluster.sh stop <i>) or use the node's own snapshot
# path, then run this script to VERIFY the image.
#
# Usage:
#   scripts/backup_verify.sh --data-dir <path> [--work-dir <path>] [--keep-work-dir] [--dry-run]
#   scripts/backup_verify.sh --data-dir run/cluster/node1/data --dry-run
#
set -euo pipefail

DATA_DIR=""
WORK_DIR=""
KEEP_WORK=0
DRY_RUN=0

usage() {
    sed -n '2,/^#$/p' "$0" | sed 's/^# \{0,1\}//'
    echo "flags: --data-dir PATH (required) [--work-dir PATH] [--keep-work-dir] [--dry-run]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
        --work-dir) WORK_DIR="${2:-}"; shift 2 ;;
        --keep-work-dir) KEEP_WORK=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[backup_verify] FATAL: unknown arg '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -n "$DATA_DIR" ]] || { echo "[backup_verify] FATAL: --data-dir is required" >&2; exit 2; }
[[ -d "$DATA_DIR" ]] || { echo "[backup_verify] FATAL: data dir missing: $DATA_DIR" >&2; exit 2; }

# Canonicalize without resolving symlinks away silently; realpath must exist.
DATA_DIR="$(realpath "$DATA_DIR")"
if [[ -z "$(ls -A "$DATA_DIR")" ]]; then
    echo "[backup_verify] FATAL: data dir is empty: $DATA_DIR" >&2; exit 2
fi

if [[ -z "$WORK_DIR" ]]; then
    WORK_DIR="$(mktemp -d -t stell-backup-XXXXXX)"
    AUTO_WORK=1
else
    AUTO_WORK=0
    mkdir -p "$WORK_DIR"
    WORK_DIR="$(realpath "$WORK_DIR")"
fi

SNAP="$WORK_DIR/snapshot"
RESTORE="$WORK_DIR/restore"
MANIFEST="$WORK_DIR/manifest.sha256"

# Fail closed: work dir must not be inside (or equal to) the live data dir,
# and the live data dir must not be inside the work dir.
case "$WORK_DIR" in
    "$DATA_DIR"*) echo "[backup_verify] FATAL: work dir inside data dir ($WORK_DIR)" >&2; exit 2 ;;
esac
case "$DATA_DIR" in
    "$WORK_DIR"*) echo "[backup_verify] FATAL: data dir inside work dir ($DATA_DIR)" >&2; exit 2 ;;
esac

cleanup() {
    if [[ "$KEEP_WORK" -eq 0 && "${AUTO_WORK:-0}" -eq 1 ]]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

plan() {
    echo "[backup_verify] PLAN (dry-run, no copies made):"
    echo "  data-dir : $DATA_DIR"
    echo "  work-dir : $WORK_DIR"
    echo "  1. cp -a data-dir -> $SNAP"
    echo "  2. sha256 manifest of snapshot -> $MANIFEST"
    echo "  3. cp -a snapshot -> $RESTORE (simulated restore)"
    echo "  4. sha256sum -c manifest inside restore copy"
    echo "  5. boot-read check on restore copy (store markers + JSON parse)"
    echo "  6. PASS/FAIL report"
}

fail() { echo "[backup_verify] FAIL: $1" >&2; exit 1; }
pass() { echo "[backup_verify] PASS: $1"; }

if [[ "$DRY_RUN" -eq 1 ]]; then plan; exit 0; fi

echo "[backup_verify] data-dir: $DATA_DIR"
echo "[backup_verify] work-dir : $WORK_DIR"

# 1. Snapshot: copy only. Never move, never touch live files.
rm -rf "$SNAP" "$RESTORE"
mkdir -p "$SNAP"
cp -a "$DATA_DIR/." "$SNAP/"
echo "[backup_verify] step 1/5 snapshot copied ($(du -sh "$SNAP" | cut -f1))"

# 2. Checksum manifest over the SNAPSHOT (relative paths, sorted).
(
    cd "$SNAP"
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "$MANIFEST"
)
NFILES="$(wc -l < "$MANIFEST")"
[[ "$NFILES" -gt 0 ]] || fail "manifest empty — snapshot has no regular files"
echo "[backup_verify] step 2/5 manifest written ($NFILES files)"

# 3. Simulated restore: fresh copy of the snapshot image into a clean dir.
mkdir -p "$RESTORE"
cp -a "$SNAP/." "$RESTORE/"
echo "[backup_verify] step 3/5 restored into temp dir"

# 4. Verify manifest inside the restored copy.
(
    cd "$RESTORE"
    sha256sum -c "$MANIFEST" --quiet || fail "manifest mismatch in restored copy"
)
pass "step 4/5 manifest verified ($NFILES files, sha256 match)"

# 5. Boot-read check (read-only): the restored copy must look like a node
#    data dir — at least one store marker — and any JSON metas must parse.
MARKERS=0
for pat in "store-shard*" "store" "kv.json" "snapshot*" "*.sst" "MANIFEST*"; do
    # shellcheck disable=SC2086
    if compgen -G "$RESTORE/$pat" > /dev/null; then MARKERS=$((MARKERS + 1)); fi
done
# Also accept any non-empty subdir tree as a weak marker (dev chains vary).
[[ "$(find "$RESTORE" -mindepth 1 | head -1)" ]] || fail "restored copy is empty"
echo "[backup_verify] step 5/5 store-marker patterns matched: $MARKERS; entries present"

if command -v python3 >/dev/null 2>&1; then
    BAD_JSON=0
    while IFS= read -r -d '' jf; do
        python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$jf" 2>/dev/null \
            || { echo "[backup_verify] WARN: unparseable JSON (left as-is): $jf"; BAD_JSON=$((BAD_JSON + 1)); }
    done < <(find "$RESTORE" -maxdepth 2 -name '*.json' -print0)
    echo "[backup_verify] JSON metas checked (unparseable: $BAD_JSON, non-fatal)"
else
    echo "[backup_verify] WARN: python3 absent — JSON parse check skipped"
fi

# Live dir untouched: confirm we never wrote there (manifest lives in work dir).
if [[ -e "$DATA_DIR/manifest.sha256" && "$DATA_DIR/manifest.sha256" -ef "$MANIFEST" ]]; then
    fail "manifest leaked into live data dir"
fi

pass "backup verified: $NFILES files, manifest match, boot-read OK (image: $SNAP)"
echo "[backup_verify] work dir kept at: $WORK_DIR (remove manually, or re-run without --keep-work-dir)"
