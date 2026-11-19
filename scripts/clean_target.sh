#!/usr/bin/env bash
# clean_target.sh — reclaim disk from a Cargo `target/` directory.
#
# SAFE BY DEFAULT: prints the plan and deletes nothing. Deletion requires --yes.
# Invariants (checked in code, not just documentation):
#   * `target/release` is NEVER removed, in any mode.
#   * `target/debug/deps` is preserved unless `--aggressive` is also passed.
#   * the `target/` root itself is never removed.
#   * destructive runs refuse to start while a cargo/rustc process is active
#     (override with --force only when you know those builds are unrelated).
#
# Usage:
#   scripts/clean_target.sh                     # dry run (default)
#   scripts/clean_target.sh --yes               # remove target/debug/incremental
#   scripts/clean_target.sh --yes --aggressive  # also deps/build/examples/.fingerprint
#   scripts/clean_target.sh --target-dir infnode/target --yes
#   scripts/clean_target.sh --help
#
# Typical effect on the node workspace (measured 2026-11-19):
#   default     frees ~17 GB, keeps deps -> only workspace crates recompile.
#   --aggressive frees ~26 GB, removes deps -> next build recompiles every
#                dependency (slow, but recovers the most space).
# See "Disk budget and target cleanup" in docs/CI.md.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="$ROOT/stellereum/target"
APPLY=0
AGGRESSIVE=0
FORCE=0

usage() {
    sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run)
            APPLY=0
            ;;
        --yes|-y)
            APPLY=1
            ;;
        --aggressive)
            AGGRESSIVE=1
            ;;
        --force)
            FORCE=1
            ;;
        --target-dir)
            [ "$#" -ge 2 ] || { echo "clean_target: --target-dir needs a path" >&2; exit 2; }
            TARGET_DIR="$2"
            shift
            ;;
        --target-dir=*)
            TARGET_DIR="${1#--target-dir=}"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "clean_target: unknown argument '$1' (try --help)" >&2
            exit 2
            ;;
    esac
    shift
done

# Resolve to an absolute path so every rm target is unambiguous.
if [ ! -d "$TARGET_DIR" ]; then
    echo "clean_target: target directory does not exist: $TARGET_DIR" >&2
    exit 4
fi
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"

case "$TARGET_DIR" in
    */target) ;;
    *)
        echo "clean_target: refusing to operate on '$TARGET_DIR' (not a .../target directory)" >&2
        exit 4
        ;;
esac

if [ ! -d "$TARGET_DIR/debug" ] && [ ! -d "$TARGET_DIR/release" ]; then
    echo "clean_target: '$TARGET_DIR' has neither debug/ nor release/; not a Cargo target dir" >&2
    exit 4
fi

# Candidates. Never add `release` here; the guard below is belt-and-braces.
CANDIDATES=("$TARGET_DIR/debug/incremental")
if [ "$AGGRESSIVE" -eq 1 ]; then
    CANDIDATES+=(
        "$TARGET_DIR/debug/deps"
        "$TARGET_DIR/debug/build"
        "$TARGET_DIR/debug/examples"
        "$TARGET_DIR/debug/.fingerprint"
    )
fi

for path in "${CANDIDATES[@]}"; do
    case "$path" in
        "$TARGET_DIR/release"|"$TARGET_DIR/release/"*)
            echo "clean_target: internal error: refusing release path $path" >&2
            exit 4
            ;;
        "$TARGET_DIR")
            echo "clean_target: internal error: refusing target root" >&2
            exit 4
            ;;
    esac
done

cargo_busy() {
    pgrep -x cargo >/dev/null 2>&1 || pgrep -x rustc >/dev/null 2>&1
}

refuse_if_busy() {
    if [ "$FORCE" -eq 0 ] && cargo_busy; then
        echo "clean_target: cargo/rustc is running; refusing to delete build state." >&2
        echo "              wait for the build, or re-run with --force if it is unrelated." >&2
        echo "              (a dry run is always safe: scripts/clean_target.sh)" >&2
        exit 3
    fi
}

busy=0
if cargo_busy; then
    busy=1
fi

if [ "$APPLY" -eq 1 ]; then
    refuse_if_busy
fi

human() {
    # $1 = bytes
    awk -v b="$1" 'BEGIN {
        split("B KB MB GB TB", u, " ");
        i = 1;
        while (b >= 1024 && i < 5) { b /= 1024; i++ }
        printf (i == 1 ? "%.0f%s" : "%.1f%s"), b, u[i]
    }'
}

if [ "$APPLY" -eq 1 ]; then
    echo "clean_target: APPLY  target=$TARGET_DIR aggressive=$AGGRESSIVE"
else
    echo "clean_target: DRY RUN (pass --yes to delete)  target=$TARGET_DIR aggressive=$AGGRESSIVE"
fi
echo "policy: target/release is never touched; target/debug/deps is kept unless --aggressive"
if [ "$busy" -eq 1 ]; then
    echo "note: cargo/rustc is currently running (destructive runs would be refused without --force)"
fi

total_bytes=0
present=0
for path in "${CANDIDATES[@]}"; do
    if [ ! -e "$path" ]; then
        echo "  absent      $path"
        continue
    fi
    bytes="$(du -sb "$path" 2>/dev/null | awk '{print $1}' || true)"
    bytes="${bytes:-0}"
    total_bytes=$((total_bytes + bytes))
    present=$((present + 1))
    if [ "$APPLY" -eq 1 ]; then
        # Re-check in case a build started after the initial guard.
        refuse_if_busy
        rm -rf -- "$path"
        echo "  removed     $(human "$bytes")  $path"
    else
        echo "  would remove $(human "$bytes")  $path"
    fi
done

echo "reclaimable: $(human "$total_bytes") across $present path(s)"
if [ "$APPLY" -eq 1 ]; then
    echo "done. target/release untouched; target/debug/deps $([ "$AGGRESSIVE" -eq 1 ] && echo 'was removed (--aggressive)' || echo 'preserved')."
else
    echo "nothing deleted. re-run with --yes to apply."
fi
