#!/usr/bin/env bash
#
# restore.sh — restore a Stellereum node from a backup.sh tarball.
#
#   scripts/backup/restore.sh <archive.tar.gz> <A|B>
#
# Procedure (exact):
#   1. systemctl stop stell-node<A|B> (if systemd manages it), then WAIT for the
#      process to exit. The sled lock on ./data/store/db is released on exit.
#   2. Scan /proc: if ANY process still has the node dir as its cwd, REFUSE.
#      Restoring under a live node corrupts the store. This script will NEVER
#      `kill -9` a running node to force it — investigate and stop it cleanly.
#   3. Snapshot the CURRENT state to $BACKUP_DIR/pre-restore-node<A|B>-<ts>.tar.gz
#      so a bad restore is reversible.
#   4. Extract the archive over $ROOT (default /root), re-enforce 600/700 key permissions.
#   5. Print `systemctl start ...` for the operator. This script does NOT start
#      the node itself — verify first (`tar -tzf`, diff node.yaml if unsure).
#
# Paths are rooted at ${STELL_ROOT:-/root} (same as backup.sh) so restores are
# dry-runnable off-host with STELL_ROOT=/tmp/fake-root.
#
# Genesis-fingerprint safety net (NOT a bug): if the tarball predates a genesis
# change (validator set, balances, STELL_FAUCET_KEY), the node REFUSES to start
# with "genesis state root mismatch for this data directory". See BACKUP.md.
# That refusal is the node protecting you from joining the wrong chain.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: restore.sh <archive.tar.gz> <A|B>
  example: restore.sh /root/backups/stell-nodeA-20260926T120000Z.tar.gz A
EOF
}

[ $# -eq 2 ] || { usage >&2; exit 2; }
ARCHIVE="$1"
NODE="$2"

case "$NODE" in
  A|B) ;;
  *) echo "error: node must be A or B (got '$NODE')" >&2; exit 2 ;;
esac
[ -f "$ARCHIVE" ] || { echo "error: archive not found: $ARCHIVE" >&2; exit 2; }

ROOT="${STELL_ROOT:-/root}"
DIR="$ROOT/node$NODE"
ENV="$ROOT/env.$NODE"
UNIT="stell-node$NODE"
DEST="${BACKUP_DIR:-$ROOT/backups}"

# Any live process rooted in the node dir holds (or is about to take) the sled
# lock. /proc scan: readlink /proc/PID/cwd, no signals sent, nothing killed.
holders_of() {
  local pid cwd
  for pid in $(pgrep -f '/stellereum/target/release/stellereum run' 2>/dev/null || true); do
    cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
    [ "$cwd" = "$DIR" ] && printf '%s\n' "$pid"
  done
}

echo "== $UNIT: stopping the unit first =="
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files "$UNIT.service" >/dev/null 2>&1; then
  systemctl stop "$UNIT" 2>/dev/null || true
  for _ in $(seq 1 300); do
    systemctl is-active --quiet "$UNIT" 2>/dev/null || break
    sleep 0.1
  done
  if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
    echo "error: $UNIT is still active after stop — refusing to restore over it" >&2
    exit 1
  fi
else
  echo "(no $UNIT unit installed — falling back to the /proc check only)"
fi

HOLDERS="$(holders_of)"
if [ -n "$HOLDERS" ]; then
  # shellcheck disable=SC2086
  echo "error: refusing restore — live process holds the sled lock (cwd $DIR): pid(s) $HOLDERS" >&2
  echo "stop it cleanly (systemctl stop $UNIT), wait for exit, then retry. Never kill -9 then restore." >&2
  exit 1
fi
echo "lock check ok: no process rooted in $DIR"

# The archive must be one of ours: refuse mystery tarballs before touching data.
MEMBERS="$(tar -tzf "$ARCHIVE" 2>/dev/null)" || { echo "error: cannot list $ARCHIVE" >&2; exit 1; }
for want in "node$NODE/node.yaml" "node$NODE/data" "node$NODE/keys" "env.$NODE"; do
  grep -qx "$want" <<<"$MEMBERS" || [ -n "$(grep "^$want/" <<<"$MEMBERS" || true)" ] || {
    echo "error: $ARCHIVE is not a node$NODE backup (member missing: $want)" >&2
    exit 1
  }
done

# Reversible-restore snapshot of the CURRENT state (best effort but fatal on
# failure: better to abort than to destroy unrecoverable state).
mkdir -p "$DEST"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
SAFETY="$DEST/pre-restore-node$NODE-$TS.tar.gz"
if [ -d "$DIR" ]; then
  HAVE="node$NODE/node.yaml"
  [ -f "$DIR/node.yaml" ] || HAVE=""
  [ -d "$DIR/data" ] && HAVE="$HAVE node$NODE/data"
  [ -d "$DIR/keys" ] && HAVE="$HAVE node$NODE/keys"
  [ -f "$ENV" ] && HAVE="$HAVE env.$NODE"
  if [ -n "$HAVE" ]; then
    # shellcheck disable=SC2086
    tar -czpf "$SAFETY" -C "$ROOT" $HAVE
    chmod 600 "$SAFETY"
    echo "current state snapshotted: $SAFETY"
  fi
fi

# Overwrite with the backup. -p keeps modes; re-enforce afterwards in case the
# tarball was unpacked oddly or umask interfered.
tar -xzpf "$ARCHIVE" -C "$ROOT"
chmod 700 "$DIR/keys"
# The glob must not fail the restore (set -e) when a keys dir is legitimately
# empty in a dry-run fixture; real backups always carry key files, and the
# node refuses to start without them, so silence here loses nothing.
chmod 600 "$DIR"/keys/* "$ENV" 2>/dev/null || chmod 600 "$ENV"
[ -f "$DIR/node.yaml" ] || { echo "error: restore left no $DIR/node.yaml — see $SAFETY" >&2; exit 1; }
[ -d "$DIR/data/store" ] || echo "warn: $DIR/data/store absent after restore (fresh-chain backup?)"

echo "restore ok: $ARCHIVE -> $DIR (+ $ENV)"
echo "verify:   tar -tzf $ARCHIVE | head; diff <(tar -xzOf $ARCHIVE node$NODE/node.yaml) $DIR/node.yaml"
echo "start it: systemctl start $UNIT && journalctl -u $UNIT -f"
echo "note: if the node exits with 'genesis state root mismatch', the backup"
echo "predates a genesis change — that refusal is the safety net, not a bug."
echo "Either restore the matching config or wipe ./data for a new chain (see BACKUP.md)."
