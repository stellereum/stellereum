#!/usr/bin/env bash
# Export HDAE program docs (repo-root docs/specs, inventories, runbooks) into
# stellereum/docs/program/ so the GitHub crate-mirror carries the full story.
# Local-only tooling: run before every GitHub sync push. Idempotent (cp -u).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/stellereum/docs/program"
mkdir -p "$DEST/specs" "$DEST/ops"
cp -u "$ROOT"/docs/PQ_*.md "$ROOT"/docs/CLASSICAL_*.md "$ROOT"/docs/MEV_*.md "$ROOT"/docs/PUBLIC_TESTNET_CODE_GAPS.md "$ROOT"/docs/WORKCHAIN_DECISION.md \
      "$ROOT"/docs/LIGHT_CLIENT_VERIFY.md "$ROOT"/docs/FUZZING.md "$ROOT"/docs/TEMPO_*.md \
      "$DEST/" 2>/dev/null || true
cp -u "$ROOT"/docs/specs/*.md "$DEST/specs/" 2>/dev/null || true
cp -u "$ROOT"/ops/*.md "$DEST/ops/" 2>/dev/null || true
cat > "$DEST/README_MIRROR.md" <<'EOF'
# program/ — mirror of the HDAE workspace docs
Files here are COPIES of the authoritative docs at the workspace root
(`docs/`, `docs/specs/`, `ops/`) exported for the GitHub crate mirror.
Do not edit here — edit the root originals and re-run
`scripts/export_program_docs.sh` before pushing.
EOF
echo "exported $(ls "$DEST"/*.md 2>/dev/null | wc -l) docs + $(ls "$DEST/specs"/*.md 2>/dev/null | wc -l) specs + $(ls "$DEST/ops"/*.md 2>/dev/null | wc -l) ops runbooks"
