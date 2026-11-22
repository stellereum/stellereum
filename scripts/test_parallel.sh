#!/usr/bin/env bash
# test_parallel.sh — run the Stellereum test suite with PER-BINARY parallelism.
#
# WHY: `cargo test` links 300+ integration binaries and then runs them ONE
# AFTER ANOTHER on a single core, so a 12-core box finishes a ~20-minute suite
# while 11 cores idle. This script keeps cargo for the build (so the test
# profile, feature set and fingerprints are exactly `cargo test`'s) and then
# runs the produced binaries concurrently, one test binary per worker slot.
#
# USAGE
#   scripts/test_parallel.sh                 # whole workspace member (lib+bins+tests)
#   scripts/test_parallel.sh --lib           # only the lib unit tests
#   scripts/test_parallel.sh -p stellereum   # one package
#   scripts/test_parallel.sh --test-item consensus_liveness_harness ...
#   JOBS=6 scripts/test_parallel.sh          # cap parallelism (default: nproc)
#   TEST_THREADS=4 scripts/test_parallel.sh  # threads INSIDE one binary (default 1)
#
# EXIT CODE: 0 only when every binary passed (or was filtered out).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JOBS="${JOBS:-$(nproc)}"
TEST_THREADS="${TEST_THREADS:-1}"
LOGDIR="${LOGDIR:-/tmp/opencode/test_parallel}"
CARGO_ARGS=()

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--package) CARGO_ARGS+=("-p" "$2"); shift 2 ;;
    --lib) CARGO_ARGS+=("--lib"); shift ;;
    --test|--test-item) CARGO_ARGS+=("--test" "$2"); shift 2 ;;
    --bin) CARGO_ARGS+=("--bin" "$2"); shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) CARGO_ARGS+=("$1"); shift ;;
  esac
done

if [ ${#CARGO_ARGS[@]} -eq 0 ]; then
  CARGO_ARGS=(-p stellereum)
fi

mkdir -p "$LOGDIR"
BUILD_LOG="$LOGDIR/build.log"
# The workspace manifest is stellereum/Cargo.toml (no root workspace), so the
# build must run from that crate; paths in the JSON plan stay absolute.
cd "$ROOT/stellereum"

echo "[test-parallel] building test binaries (cargo test --no-run)..."
if ! cargo test --no-run --message-format=json "${CARGO_ARGS[@]}" \
      > "$LOGDIR/build.json" 2> "$BUILD_LOG"; then
  echo "[test-parallel] BUILD FAILED (see $BUILD_LOG)" >&2
  tail -n 40 "$BUILD_LOG" >&2
  exit 1
fi

# Parse every produced test executable. `executable` is null for non-test
# artifacts, so this also filters out rlibs/bins that cargo happened to build.
python3 - "$LOGDIR/build.json" "$LOGDIR/plan.tsv" <<'PY'
import json, sys
src, out = sys.argv[1], sys.argv[2]
rows = {}
with open(src, errors="ignore") as fh:
    for line in fh:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            m = json.loads(line)
        except Exception:
            continue
        if m.get("reason") != "compiler-artifact":
            continue
        exe = m.get("executable")
        if not exe:
            continue
        target = m.get("target", {})
        # ONLY test harnesses. Cargo also emits the path of every plain
        # `[[bin]]` it builds (e.g. `stellereum`, `abi_codegen`); running those
        # with `--test-threads` would execute the real binary and fail. The
        # authoritative flag is `profile.test`.
        if not m.get("profile", {}).get("test", False):
            continue
        kinds = target.get("kind", [])
        if not any(k in ("test", "lib", "bin") for k in kinds):
            continue
        # The REAL binaries are also built here (`target/debug/stellereum`,
        # `abi_codegen`); only the hashed harnesses under `deps/` are test
        # executables. Running a real binary with `--test-threads` starts the
        # node, which is not what the gate means.
        if "/deps/" not in exe:
            continue
        rows[exe] = target.get("name", "?")
with open(out, "w") as fh:
    for exe, name in sorted(rows.items(), key=lambda kv: kv[1]):
        fh.write(f"{name}\t{exe}\n")
print(f"[test-parallel] planned {len(rows)} test binaries")
PY

if [ ! -s "$LOGDIR/plan.tsv" ]; then
  echo "[test-parallel] no test binaries planned — nothing to run"
  exit 0
fi

export TEST_THREADS LOGDIR
run_one() {
  local name="$1" exe="$2"
  # Unique log per HARNESS: the lib and bin harnesses are both named after the
  # crate, so a name-only log would interleave two different runs.
  local tag
  tag="$(basename "$exe")"
  local log="$LOGDIR/${name}__${tag}.log"
  # Each binary gets its own CPU budget: TEST_THREADS inside, JOBS binaries at once.
  if ! "$exe" --test-threads="$TEST_THREADS" > "$log" 2>&1; then
    echo "FAIL $name"
    return 1
  fi
  echo "ok   $name"
  return 0
}
export -f run_one

START=$(date +%s)
set +e
RESULTS=$(awk -F'\t' '{print $1"\t"$2}' "$LOGDIR/plan.tsv" \
  | xargs -P "$JOBS" -I{} bash -c 'IFS=$'"'"'\t'"'"' read -r n e <<< "{}"; run_one "$n" "$e"')
RC=$?
set -e
ELAPSED=$(( $(date +%s) - START ))

FAILED=$(printf '%s\n' "$RESULTS" | grep -c '^FAIL' || true)
PASSED=$(printf '%s\n' "$RESULTS" | grep -c '^ok' || true)
echo
echo "[test-parallel] $PASSED binaries passed, $FAILED failed in ${ELAPSED}s (jobs=$JOBS, threads=$TEST_THREADS)"

if [ "$FAILED" -ne 0 ]; then
  echo "[test-parallel] failing binaries (full logs in $LOGDIR):"
  printf '%s\n' "$RESULTS" | grep '^FAIL' | sed 's/^FAIL /  - /'
  exit 1
fi
exit 0
