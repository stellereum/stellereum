#!/usr/bin/env bash
# merge_verified.sh — merge only fully-passing agent branches (HDAE Phase 5).
# Usage: ./scripts/agents/merge_verified.sh <agents-base-dir>
# For each worktree: gate-crate on its scope, merge on green, report on red.
set -u
BASE="${1:?agents base dir}"
MAIN="$BASE/../stellereum-project"
[ -d "$MAIN/.git" ] || { echo "NO GIT REPO"; exit 1; }
for wt in "$BASE"/agent_*; do
  [ -d "$wt" ] || continue
  scope=$(grep -oP '(?<=crate scope: ).*' "$wt/.agent_env" 2>/dev/null || echo "?")
  br=$(git -C "$wt" branch --show-current)
  echo "=== $br (scope: $scope) ==="
  if (cd "$wt/$scope" && cargo clippy --all-targets -- -D warnings && cargo test --no-fail-fast); then
    git -C "$MAIN" merge --no-ff "$br" -m "merge $br (gate green)" \
      && echo "MERGED $br" || echo "CONFLICT $br — human required"
  else
    echo "RED $br — not merged (see log above)"
  fi
done
