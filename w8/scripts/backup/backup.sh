#!/usr/bin/env bash
#
# backup.sh — snapshot a Stellereum node (data + keys + config + env) to a
# timestamped tarball, verify it, and prune old snapshots.
#
#   scripts/backup/backup.sh [--node A|B|all] [--dir DIR] [--keep N]
#
# Defaults: --node all, --dir ${BACKUP_DIR:-$ROOT/backups}, --keep ${BACKUP_KEEP:-7},
# where $ROOT is ${STELL_ROOT:-/root} (STELL_ROOT exists for off-host dry-runs).
#
# What goes into the tarball (members are relative to $ROOT, permissions kept):
#   nodeA/node.yaml  nodeA/data/  nodeA/keys/  env.A        (for --node A)
#   nodeB/node.yaml  nodeB/data/  nodeB/keys/  env.B        (for --node B)
# Both sets for --node all, packed as ONE tarball per node.
#
# The env file is copied as BYTES (tar), never sourced and never printed: this
# script only ever echoes file NAMES. Treat tarballs as secrets (keys + env
# inside): they are written mode 600. Never commit them.
#
# Sled note: a tarball taken while the node is RUNNING can catch ./data/store
# mid-write. sled is crash-safe so the node itself is fine, but for a restore
# you can trust, prefer:  systemctl stop stell-nodeA (resp. B)  first.
# This script warns when the unit/process looks active but still proceeds.
set -euo pipefail

NODE_SEL="all"
ROOT="${STELL_ROOT:-/root}"
DEST="${BACKUP_DIR:-$ROOT/backups}"
KEEP="${BACKUP_KEEP:-7}"

usage() {
  cat <<'EOF'
usage: backup.sh [--node A|B|all] [--dir DIR] [--keep N]
  --node  which node to back up (default: all)
  --dir   destination directory (default: $BACKUP_DIR or /root/backups)
  --keep  how many newest tarballs to keep per node (default: $BACKUP_KEEP or 7)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --node) NODE_SEL="${2:?--node needs A, B or all}"; shift 2 ;;
    --dir)  DEST="${2:?--dir needs a directory}"; shift 2 ;;
    --keep) KEEP="${2:?--keep needs a number}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$NODE_SEL" in
  A|B|all) ;;
  *) echo "error: --node must be A, B or all (got '$NODE_SEL')" >&2; exit 2 ;;
esac
case "$KEEP" in
  ''|*[!0-9]*|0) echo "error: --keep must be a positive integer (got '$KEEP')" >&2; exit 2 ;;
esac

mkdir -p "$DEST"
TS="$(date -u +%Y%m%dT%H%M%SZ)"

# Warn (names only, never values) if the node looks live: a hot tarball of the
# sled store can be torn. Proceed anyway — stopping is the operator's call.
warn_if_live() {
  local unit="$1" dir="$2" pid cwd
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$unit" 2>/dev/null; then
    echo "warn: $unit is active — stopping it first gives a trustworthy backup" >&2
    return 0
  fi
  for pid in $(pgrep -f '/stellereum/target/release/stellereum run' 2>/dev/null || true); do
    cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
    if [ "$cwd" = "$dir" ]; then
      echo "warn: pid $pid still runs with cwd $dir — stopping it first gives a trustworthy backup" >&2
      return 0
    fi
  done
}

backup_one() {
  local node="$1"           # A or B
  local dir="$ROOT/node$node"
  local env="$ROOT/env.$node"
  local unit="stell-node$node"
  local archive="$DEST/stell-node$node-$TS.tar.gz"

  [ -d "$dir" ]      || { echo "error: $dir missing" >&2; return 1; }
  [ -f "$dir/node.yaml" ] || { echo "error: $dir/node.yaml missing" >&2; return 1; }
  [ -d "$dir/data" ] || { echo "error: $dir/data missing" >&2; return 1; }
  [ -d "$dir/keys" ] || { echo "error: $dir/keys missing" >&2; return 1; }
  [ -f "$env" ]      || { echo "error: $env missing" >&2; return 1; }

  warn_if_live "$unit" "$dir"

  # -p preserves the 600/700 key material modes; -C "$ROOT" keeps members
  # relocatable (restore with -C "$ROOT"). Names only on stdout — no secrets.
  tar -czpf "$archive" -C "$ROOT" \
    "node$node/node.yaml" "node$node/data" "node$node/keys" "env.$node"
  chmod 600 "$archive"

  # Verify: the tarball must list correctly right after writing.
  local members
  members="$(tar -tzf "$archive")" || { echo "error: $archive failed verification (unreadable)" >&2; return 1; }
  for want in "node$node/node.yaml" "node$node/data" "node$node/keys" "env.$node"; do
    grep -qx "$want" <<<"$members" || [ -n "$(grep "^$want/" <<<"$members" || true)" ] || {
      echo "error: $archive failed verification (member missing: $want)" >&2
      return 1
    }
  done

  # Retention: keep the N newest tarballs for this node, delete the rest.
  local count=0 f
  while IFS= read -r f; do
    count=$((count + 1))
    if [ "$count" -gt "$KEEP" ]; then
      rm -f "$f"
      echo "pruned old backup: $f"
    fi
  done < <(ls -1t "$DEST"/stell-node"$node"-*.tar.gz 2>/dev/null || true)

  echo "backup ok: $archive"
}

case "$NODE_SEL" in
  all) backup_one A; backup_one B ;;
  *)   backup_one "$NODE_SEL" ;;
esac
