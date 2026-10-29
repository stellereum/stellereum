#!/usr/bin/env bash
# harness_status.sh — machine-generated STATUS.md + artifacts/harness_status.json
# (HDAE Phase 4). Agents MUST NOT hand-edit STATUS.md; this script owns it.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/artifacts"
RUST_WS="stellereum infmail-valid-backend stellereum-contracts stellereum-indexer stellereum-sdk stell-wallet scripts/tools/stelops"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

json='{"generated_utc":"'$TS'","workspaces":{'
md="# STATUS (machine-generated, $TS)"
md="$md
_Do not edit by hand — run ./scripts/harness_status.sh._
"
for ws in $RUST_WS; do
  if [ ! -f "$ROOT/$ws/Cargo.toml" ]; then
    json="$json\"$ws\":{\"present\":false},"
    md="$md
- \`$ws\`: no manifest"
    continue
  fi
  counts=$(cd "$ROOT/$ws" && cargo clippy --all-targets --message-format short 2>&1)
  w=$(echo "$counts" | grep -c ": warning" || true)
  e=$(echo "$counts" | grep -c ": error" || true)
  json="$json\"$ws\":{\"present\":true,\"clippy_warnings\":$w,\"clippy_errors\":$e},"
  md="$md
- \`$ws\`: clippy warnings=$w errors=$e"
done
# fake-code scan state (XXX only as whole-word marker, not inside literals)
fakes=$(rg -l --glob '*.rs' -g '!target/**' -g '!node_modules/**' -g '!.archive/**' 'todo!\(|unimplemented!\(|FIXME|\bXXX\b' "$ROOT" 2>/dev/null | wc -l)
json="${json%,},\"fake_code_files\":$fakes"
md="$md
- fake-code files: $fakes (must be 0)
- specs: docs/specs/01-04 + CRATE_ISOLATION_PLAN.md
- archive: .archive/legacy_agent_notes/ ($(ls "$ROOT/.archive/legacy_agent_notes" 2>/dev/null | wc -l) files)"
json="$json}}"
echo "$json" | python3 -m json.tool > "$ROOT/artifacts/harness_status.json"
printf "%s\n" "$md" > "$ROOT/STATUS.md"
cat "$ROOT/STATUS.md"
