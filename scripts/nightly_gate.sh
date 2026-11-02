#!/usr/bin/env bash
# nightly_gate.sh — wave-4 nightly QA gate (clippy + lib + fuzz + matrix + repro).
#
# Manual cron (root has no .github/workflows — checked — so the schedule lives here):
#   0 2 * * * cd /home/imm/stellereum-project && ./scripts/nightly_gate.sh >> artifacts/nightly.log 2>&1
#
# Stages (each referenced command/flag verified to exist in-tree):
#   1. clippy:  (cd stellereum && cargo clippy --all-targets -- -D warnings)
#   2. lib:     (cd stellereum && cargo test --lib --no-fail-fast)
#   3. fuzz:    (cd stellereum && cargo test --test fuzz_economics_ext --no-fail-fast)
#   4. matrix:  ./scripts/feature_matrix.sh   (takes NO flags; rows carry own timeouts)
#   5. repro:   ./stellereum/scripts/audit-repro.sh --quick
#               (canonical path: root scripts/audit-repro.sh does NOT exist;
#               --quick is a verified flag of stellereum/scripts/audit-repro.sh)
# Exit 0 = all green. Any failure prints [NIGHTLY FAIL] and exits nonzero.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." || exit 1; pwd)"
STELL="$ROOT/stellereum"

pass() { echo "[NIGHTLY PASS] $1"; }
fail() { echo "[NIGHTLY FAIL] $1"; exit 1; }
info() { echo "[nightly] $1"; }

info "root: $ROOT"
info "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

info "stage 1: clippy --all-targets -D warnings (stellereum)"
(cd "$STELL" && cargo clippy --all-targets -- -D warnings) \
  || fail "stage 1: clippy"
pass "stage 1: clippy clean"

info "stage 2: full lib tests (stellereum)"
(cd "$STELL" && cargo test --lib --no-fail-fast) \
  || fail "stage 2: lib tests"
pass "stage 2: lib green"

info "stage 3: deterministic economics fuzz battery"
(cd "$STELL" && cargo test --test fuzz_economics_ext --no-fail-fast) \
  || fail "stage 3: fuzz_economics_ext"
pass "stage 3: fuzz battery green"

info "stage 4: feature matrix (./scripts/feature_matrix.sh, no flags)"
"$ROOT/scripts/feature_matrix.sh" \
  || fail "stage 4: feature matrix has RED rows"
pass "stage 4: matrix all green (or SKIP)"

info "stage 5: audit repro smoke (stellereum/scripts/audit-repro.sh --quick)"
"$STELL/scripts/audit-repro.sh" --quick \
  || fail "stage 5: audit repro"
pass "stage 5: audit repro green"

echo "NIGHTLY: all gates green."
