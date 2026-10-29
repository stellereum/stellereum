#!/usr/bin/env bash
# verify_testnet_ideal.sh — THE STRICT GATEKEEPER (HDAE Phase 4).
# Usage: ./scripts/verify_testnet_ideal.sh [--fast] [--no-sim]
#   --fast    : lib tests only for the big stellereum crate (CI quick path)
#   --no-sim  : skip the 4-node sim harness (unit+clippy only)
# Exit 0 = ideal. Anything else = FAIL with the stage that broke.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAST=0; SIM=1
for a in "$@"; do
  case "$a" in
    --fast) FAST=1 ;;
    --no-sim) SIM=0 ;;
  esac
done
pass() { echo "[GATE PASS] $1"; }
fail() { echo "[GATE FAIL] $1"; exit 1; }
info() { echo "[gate] $1"; }

RUST_WS="stellereum infnode stellereum-contracts stellereum-indexer stellereum-sdk stell-wallet scripts/tools/stelops"

# ---- STAGE 0: fake-code scan (hard fail) ----
info "stage 0: fake-code scan"
if rg -n --glob '*.rs' -g '!target/**' -g '!node_modules/**' -g '!.archive/**' \
    'todo!\(|unimplemented!\(|FIXME|\bXXX\b' "$ROOT" > "$ROOT/artifacts/fakescan.txt" 2>/dev/null; then
  : # rg exit 0 = matches found even with redirect; check file size instead
fi
if [ -s "$ROOT/artifacts/fakescan.txt" ]; then
  echo "--- forbidden patterns ---"; cat "$ROOT/artifacts/fakescan.txt"
  fail "stage 0: todo!/unimplemented!/FIXME/XXX-marker found"
fi
pass "stage 0: no fake code"
# advisory: 'dummy' is legitimate in this repo (WAT $dummy params, attacker
# docs, test fixtures) — report, do not fail.
DUMMY_N=$(rg -l --glob '*.rs' -g '!target/**' -g '!node_modules/**' -g '!.archive/**' 'dummy' "$ROOT" 2>/dev/null | wc -l)
info "advisory: 'dummy' appears in $DUMMY_N rs files (known-legit, see gate docs)"

# ---- STAGE 1: clippy -D warnings, every workspace ----
info "stage 1: clippy --all-targets -- -D warnings"
for ws in $RUST_WS; do
  if [ ! -f "$ROOT/$ws/Cargo.toml" ]; then info "skip $ws (no manifest)"; continue; fi
  (cd "$ROOT/$ws" && cargo clippy --all-targets -- -D warnings) \
    || fail "stage 1: clippy in $ws"
  pass "stage 1: $ws"
done

# ---- STAGE 2: rustfmt (hard gate — tree was fmt-cleaned 2026-10-29) ----
info "stage 2: rustfmt check"
for ws in $RUST_WS; do
  if [ -f "$ROOT/$ws/Cargo.toml" ]; then
    (cd "$ROOT/$ws" && cargo fmt --check) >/dev/null 2>&1 \
      && info "fmt clean: $ws" || fail "stage 2: fmt dirty in $ws (run cargo fmt)"
  fi
done
pass "stage 2: rustfmt clean"

# ---- STAGE 3: tests ----
info "stage 3: tests"
RUNNER="cargo test"
command -v cargo-nextest >/dev/null 2>&1 && RUNNER="cargo nextest run" && info "using nextest"
for ws in $RUST_WS; do
  if [ ! -f "$ROOT/$ws/Cargo.toml" ]; then continue; fi
  if [ "$FAST" = 1 ] && [ "$ws" = "stellereum" ]; then
    (cd "$ROOT/$ws" && $RUNNER --lib --no-fail-fast) || fail "stage 3: $ws lib"
  else
    (cd "$ROOT/$ws" && $RUNNER --workspace --no-fail-fast) || fail "stage 3: $ws"
  fi
  pass "stage 3: $ws"
done

# ---- STAGE 4: 4-node sim harness (the virtual testnet) ----
if [ "$SIM" = 1 ]; then
  info "stage 4: sim harness (consensus_liveness_harness + proposal_refire)"
  (cd "$ROOT/stellereum" && cargo test --test consensus_liveness_harness --no-fail-fast) \
    || fail "stage 4: consensus_liveness_harness"
  (cd "$ROOT/stellereum" && cargo test --test proposal_refire_tests --no-fail-fast) \
    || fail "stage 4: proposal_refire_tests"
  pass "stage 4: sim harness"
else
  info "stage 4: skipped (--no-sim)"
fi

echo "IDEAL: all gates green."
