#!/usr/bin/env bash
# Export a clean source snapshot for external (neural/human) auditors.
# Guarantees: tracked files ONLY (untracked secrets can never leak) +
# hard-fail if secret-shaped paths are ever tracked + manifest with hashes.
# Usage: ./scripts/export_audit_snapshot.sh [out-dir]  (default: /tmp/opencode/audit-snapshot)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-/tmp/opencode/audit-snapshot}"
echo "[audit-export] root: $ROOT"

# 1. Hard-fail on tracked secrets (history + index).
if git -C "$ROOT" ls-files | grep -iE '(^|/)(keys?/|secrets?/|.*\.pem|.*\.key$|nodeC-data|\.env$|faucet.*key)' | grep -vE 'keyring\.rs|keystore_security|_tests\.rs|\.md$'; then
  echo "[audit-export] FATAL: secret-shaped tracked paths found above. Aborting." >&2
  exit 1
fi
echo "[audit-export] tracked tree: no secret material."

# 2. Export HEAD (tracked only — data dirs, keys/, target/, logs are untracked/ignored by construction).
rm -rf "$OUT"; mkdir -p "$OUT"
git -C "$ROOT" archive HEAD | tar -x -C "$OUT"
echo "[audit-export] exported $(git -C "$ROOT" ls-files | wc -l) tracked files."

# 3. Manifest: sha256 per file + HEAD + date (auditors verify integrity).
(
  cd "$OUT"
  git -C "$ROOT" rev-parse HEAD > AUDIT_HEAD
  date -u +%Y-%m-%dT%H:%M:%SZ > AUDIT_DATE
  find . -path ./.git -prune -o -type f -print0 | sort -z | xargs -0 sha256sum > AUDIT_MANIFEST.sha256
)
echo "[audit-export] manifest: $OUT/AUDIT_MANIFEST.sha256"
echo "[audit-export] snapshot ready at $OUT (upload the DIRECTORY, never the live repo)."
