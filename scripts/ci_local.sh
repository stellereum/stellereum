#!/usr/bin/env bash
# ci_local.sh — reproduce the GitHub PR/nightly gate on this machine.
#
# USAGE
#   scripts/ci_local.sh                 # fmt + clippy + lib + curated suites
#   scripts/ci_local.sh --full          # fmt + clippy + lib + ALL binaries
#   scripts/ci_local.sh --suite state   # one curated suite only
#   scripts/ci_local.sh --sdk           # also test stellereum-sdk (+ sdk-js
#                                       #   when sdk-js/node_modules exists)
#   scripts/ci_local.sh --loadtest      # also build the load-test harness
#   JOBS=8 TEST_THREADS=4 scripts/ci_local.sh --full
#
# The curated suites are the same six groups as .github/workflows/ci.yml.
# `--full` is the nightly authoritative run: scripts/test_parallel.sh with
# three binaries at a time, two threads inside each binary.
#
# NETWORK: this script performs no downloads and exports
# CARGO_NET_OFFLINE=true. On a fresh clone run `cargo fetch` once in each
# Rust workspace (or set CARGO_NET_OFFLINE=false for one run); after that the
# gate is fully offline. It never contacts the live cluster, a faucet, or a
# deploy target.
#
# EXIT CODE: 0 only when every executed stage passed. The last line is
# machine-readable:
#   CI_LOCAL_RESULT=PASS total_seconds=123 passed=4 failed=0
#   CI_LOCAL_RESULT=FAIL total_seconds=123 passed=3 failed=1
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
START_ALL=$(date +%s)

MODE="pr"
ONLY_SUITE=""
WITH_SDK=0
WITH_LOADTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --full) MODE="full"; shift ;;
    --suite)
      [ $# -ge 2 ] || { echo "--suite needs a name (consensus|state|rpc|compact|sync|xshard)" >&2; exit 2; }
      ONLY_SUITE="$2"; shift 2 ;;
    --sdk) WITH_SDK=1; shift ;;
    --loadtest) WITH_LOADTEST=1; shift ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
  esac
done

# Conservative defaults for a 4 GB runner. Override with the environment.
if [ -z "${JOBS:-}" ]; then
  if [ "$MODE" = "full" ]; then JOBS=3; else JOBS=2; fi
fi
TEST_THREADS="${TEST_THREADS:-2}"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"
export JOBS TEST_THREADS CARGO_BUILD_JOBS CARGO_NET_OFFLINE
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

echo "==> ci_local: mode=$MODE root=$ROOT"
echo "    jobs=$JOBS test_threads=$TEST_THREADS build_jobs=$CARGO_BUILD_JOBS offline=$CARGO_NET_OFFLINE"
if command -v rustc >/dev/null 2>&1; then rustc -V; fi
if command -v cargo >/dev/null 2>&1; then cargo -V; fi

SUITES=(consensus state rpc compact sync xshard)

# Keep these lists in sync with the test-suites matrix in ci.yml.
suite_tests() {
  case "$1" in
    consensus) echo "consensus_liveness_harness consensus_byzantine_tests consensus_security_tests bft_lock_safety_tests liveness_horizon_tests sim_tempo_target06_tests" ;;
    state) echo "state_root_completeness_tests state_commit_batch_tests apply_floor_tests parallel_apply_parity_tests block_packing_scale_tests" ;;
    rpc) echo "rpc_tests rpc_batch_tests rpc_ws_tests rpc_surface_audit_tests" ;;
    compact) echo "compact_gossip_tests pentest2_network_compact" ;;
    sync) echo "sync_adversarial_tests sync_walk_concurrency_tests catch_up_tests epoch_sync_tests" ;;
    xshard) echo "xshard_2pc_tests xshard_replay_tests cross_shard_e2e_pq_tests cross_shard_anchor_tests" ;;
    *) return 1 ;;
  esac
}

if [ -n "$ONLY_SUITE" ] && ! suite_tests "$ONLY_SUITE" >/dev/null; then
  echo "unknown suite: $ONLY_SUITE (expected: ${SUITES[*]})" >&2
  exit 2
fi

PASSED=()
FAILED=()
SKIPPED=()
TIMINGS=()

# Run one command in a workspace and print its own honest duration.
run_in() {
  local dir="$1" label="$2"
  shift 2
  local t0 t1 rc
  t0=$(date +%s)
  echo "-- $label"
  ( cd "$ROOT/$dir" && "$@" )
  rc=$?
  t1=$(date +%s)
  if [ "$rc" -eq 0 ]; then
    echo "   PASS ${label} ($((t1 - t0))s)"
  else
    echo "   FAIL ${label} (exit $rc, $((t1 - t0))s)"
  fi
  return "$rc"
}

# Run a named stage; never abort the whole gate so the summary is complete.
run_stage() {
  local name="$1"
  shift
  local t0 t1 rc
  t0=$(date +%s)
  echo
  echo "==> stage: $name"
  "$@"
  rc=$?
  t1=$(date +%s)
  TIMINGS+=("${name}=$((t1 - t0))s")
  if [ "$rc" -eq 0 ]; then
    PASSED+=("$name")
    echo "==> PASS $name ($((t1 - t0))s)"
  else
    FAILED+=("$name")
    echo "==> FAIL $name (exit $rc, $((t1 - t0))s)"
  fi
  return 0
}

stage_fmt() {
  local ws rc=0
  for ws in stellereum infnode stellereum-sdk; do
    run_in "$ws" "cargo fmt --all --check ($ws)" cargo fmt --all --check || rc=1
  done
  return "$rc"
}

stage_clippy() {
  local ws rc=0
  for ws in stellereum infnode; do
    run_in "$ws" "cargo clippy --all-targets -- -D warnings ($ws)" \
      cargo clippy --locked --all-targets -- -D warnings || rc=1
  done
  return "$rc"
}

stage_lib() {
  local rc=0
  run_in stellereum "cargo test --lib (stellereum)" \
    cargo test --locked --lib -- --test-threads="$TEST_THREADS" || rc=1
  run_in infnode "cargo test --lib (infnode)" \
    cargo test --locked --lib -- --test-threads="$TEST_THREADS" || rc=1
  return "$rc"
}

stage_suite() {
  local suite="$1" tests t rc=0
  tests="$(suite_tests "$suite")" || return 2
  for t in $tests; do
    run_in stellereum "cargo test --test $t ($suite)" \
      cargo test --locked --test "$t" -- --test-threads="$TEST_THREADS" || rc=1
  done
  return "$rc"
}

stage_all_suites() {
  local s rc=0
  for s in "${SUITES[@]}"; do
    stage_suite "$s" || rc=1
  done
  return "$rc"
}

stage_full() {
  run_in . "scripts/test_parallel.sh -p stellereum (JOBS=$JOBS TEST_THREADS=$TEST_THREADS)" \
    ./scripts/test_parallel.sh -p stellereum
}

stage_sdk() {
  local rc=0
  run_in stellereum-sdk "cargo test (stellereum-sdk)" cargo test --locked || rc=1
  if [ -d "$ROOT/sdk-js/node_modules" ]; then
    run_in sdk-js "npm run typecheck (sdk-js)" npm run typecheck || rc=1
    run_in sdk-js "npm test (sdk-js)" npm test || rc=1
    run_in sdk-js "npm run build (sdk-js)" npm run build || rc=1
  else
    SKIPPED+=("sdk-js(node_modules absent)")
    echo "-- SKIP sdk-js: sdk-js/node_modules is absent."
    echo "   Run 'npm ci' in sdk-js once (that step needs network), then re-run --sdk."
  fi
  return "$rc"
}

stage_loadtest() {
  run_in scripts/loadtest/loadtest "cargo build (load-test harness)" cargo build --locked
}

if [ -n "$ONLY_SUITE" ]; then
  run_stage "suite:$ONLY_SUITE" stage_suite "$ONLY_SUITE"
else
  run_stage fmt stage_fmt
  run_stage clippy stage_clippy
  run_stage test-lib stage_lib
  if [ "$MODE" = "full" ]; then
    run_stage full-parallel stage_full
  else
    run_stage test-suites stage_all_suites
  fi
  if [ "$WITH_SDK" -eq 1 ]; then
    run_stage sdk stage_sdk
  fi
  if [ "$WITH_LOADTEST" -eq 1 ]; then
    run_stage loadtest-build stage_loadtest
  fi
fi

END_ALL=$(date +%s)
TOTAL=$((END_ALL - START_ALL))

echo
echo "==== summary ===="
for t in "${TIMINGS[@]}"; do
  echo "  $t"
done

failed_csv=""
if [ "${#FAILED[@]}" -gt 0 ]; then
  failed_csv="$(IFS=,; echo "${FAILED[*]}")"
fi
skipped_csv=""
if [ "${#SKIPPED[@]}" -gt 0 ]; then
  skipped_csv="$(IFS=,; echo "${SKIPPED[*]}")"
fi

if [ -n "$skipped_csv" ]; then
  echo "CI_LOCAL_SKIPPED=$skipped_csv"
fi
if [ -n "$failed_csv" ]; then
  echo "CI_LOCAL_FAILED=$failed_csv"
fi

if [ "${#FAILED[@]}" -eq 0 ]; then
  echo "CI_LOCAL_RESULT=PASS total_seconds=$TOTAL passed=${#PASSED[@]} failed=0"
  exit 0
fi
echo "CI_LOCAL_RESULT=FAIL total_seconds=$TOTAL passed=${#PASSED[@]} failed=${#FAILED[@]}"
exit 1
