#!/usr/bin/env bash
# cluster_health.sh — the operator health screen (thin wrapper).
#
# The implementation lives in the cluster tooling, one level up:
#     <monorepo>/scripts/stell-sync.sh health
# This wrapper exists so an operator working inside the node's own directory
# has a stable path; it forwards its arguments unchanged.
#
# What it prints (see docs/OPERATIONS.md §14.5):
#   1. the validator set with every member's power, the total power, the
#      quorum and the `fragile` flag;
#   2. the shard heads (per shard: type, tip height, tip hash, local or not);
#   3. the chain tip per shard;
#   4. the indexer tip;
#   5. the RPC round-trip latency.
#
# Exit code: 0 when every check passed, 1 when any of them did not.
#
# Usage:
#   scripts/cluster_health.sh [--rpc URL] [--indexer URL] [--timeout SECS]

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The canonical implementation: the monorepo's cluster tooling, one level up.
for candidate in \
    "$HERE/../scripts/stell-sync.sh" \
    "$HERE/../../scripts/stell-sync.sh" \
    "$HERE/../../../scripts/stell-sync.sh"; do
    if [[ -x "$candidate" ]]; then
        exec "$candidate" health "$@"
    fi
done

cat >&2 <<'EOF'
cluster_health.sh: the cluster tooling (scripts/stell-sync.sh) was not found
next to this directory. Looked in:
  ../scripts/stell-sync.sh
  ../../scripts/stell-sync.sh
  ../../../scripts/stell-sync.sh
EOF
exit 2
