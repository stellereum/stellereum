#!/usr/bin/env bash
# spawn_worktrees.sh — isolated git worktrees sharing caches (HDAE Phase 5).
# Usage: ./scripts/agents/spawn_worktrees.sh <agent-id> <crate-subpath>
# NOTE: requires a git repo. This tree has none yet — step zero is:
#   git init && git add -A && git commit -m "HDAE baseline: gates green"
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ID="${1:?agent id}"; CRATE="${2:?crate subpath, e.g. stellereum}"
BASE="$(dirname "$ROOT")/$(basename "$ROOT")_agents"
[ -d "$ROOT/.git" ] || { echo "NO GIT REPO — run step zero first (see header)"; exit 1; }
mkdir -p "$BASE"
WT="$BASE/agent_${ID}_${CRATE//\//_}"
git -C "$ROOT" worktree add -b "agent/$ID/$CRATE" "$WT" HEAD || exit 1
# share caches: symlink target + sccache env hint
ln -sfn "$ROOT/target" "$WT/target" 2>/dev/null || true
cat > "$WT/.agent_env" <<EOF
# agent $ID — crate scope: $CRATE (DO NOT touch other paths)
export CARGO_TARGET_DIR=$ROOT/target-shared
export CARGO_NET_OFFLINE=false
EOF
echo "worktree ready: $WT"
echo "scope lock: $CRATE (see AGENTS.md — out-of-scope edits fail review)"
