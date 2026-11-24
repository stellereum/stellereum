#!/usr/bin/env bash
# shellcheck shell=bash
# ==============================================================================
# perf-matrix.sh — reproducible throughput/latency matrix for ONE cluster.
#
#   N validators x offered tx/s x STELL_MIN_BLOCK_MS block floor
#
# One cell = one load wave against a cluster the operator has provisioned.
# N and the block floor are cluster properties, so one invocation measures one
# (N, floor) cluster across the requested rates; run it again against another
# cluster with --reuse to fill more rows of the same results set. Every cell
# that was not measured is rendered as NOT MEASURED with a reason. The report
# never infers a number it did not collect.
#
# Raw evidence per cell (results dir):
#   cells/<id>/command.txt          exact argv, shell-quoted
#   cells/<id>/loadtest.log         full harness stdout/stderr
#   cells/<id>/report.json          harness --json-out
#   cells/<id>/metrics-before.txt   node /metrics scrape before the wave
#   cells/<id>/metrics-after.txt    node /metrics scrape after the wave
#   cells/<id>/metrics-delta.json   bucket deltas + interpolated quantiles
#   cells/<id>/cell.json            normalized row (the report reads this)
#   meta.json / summary.md / matrix.jsonl / senders.txt
#
# SAFETY
#   * refuses the known public/validator hosts by literal hostname match;
#   * requires --i-know-this-is-not-mainnet;
#   * refuses a non-loopback endpoint without --allow-remote;
#   * each cell runs under a hard `timeout`; cells run strictly one at a time.
#
# This script never builds anything unless --build is passed, never restarts a
# node, never funds an account and never edits node state.
# ==============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DELTA_AWK="$ROOT/scripts/loadtest/metrics-delta.awk"
ORIG_ARGS=("$@")

PUBLIC_HOSTS=(
  "212.113.103.105"
  "213.21.246.5"
  "138.124.102.200"
  "178.155.74.242"
  "77.110.96.68"
  "rpc.stellereum.org"
)

RPC=""
METRICS_URL=""
VALIDATORS=""
BLOCK_FLOOR_MS=""
RATES="100,1000,5000"
MATRIX_NS="4,32,128"
MATRIX_FLOORS="400,250"
SENDERS=128
DURATION=60
DRAIN_TIMEOUT=180
SETTLE=30
PER_CELL_TIMEOUT=0
OUT=""
HARNESS="$ROOT/scripts/loadtest/loadtest/target/release/stell-loadtest"
HARNESS_MANIFEST="$ROOT/scripts/loadtest/loadtest/Cargo.toml"
BUILD=0
REUSE=1
FORCE=0
ACK=0
ALLOW_REMOTE=0
LOCAL_CLUSTER=0
CPU_PIDS=""
MAX_429_SHARE="0.01"
ALLOW_VALIDATOR_MISMATCH=0
ALLOW_FLOOR_MISMATCH=0
PLAN=0
RENDER_ONLY=""
FLOOR_VERIFIED=0
CHAIN_ID=""

usage() {
  cat <<'EOF'
perf-matrix.sh — one-cluster throughput/latency matrix (N x tx/s x block floor)

USAGE
  scripts/perf-matrix.sh --rpc URL --validators N --block-floor-ms MS \
      --i-know-this-is-not-mainnet [options]

REQUIRED
  --rpc URL                    explicit JSON-RPC endpoint (never the public one)
  --validators N              validator count of the cluster under test
  --block-floor-ms MS         STELL_MIN_BLOCK_MS the cluster runs with
  --i-know-this-is-not-mainnet acknowledgement; there is no default

CLUSTER
  --metrics-url URL           node Prometheus endpoint (…/metrics). Without it,
                              apply/block/CPU metric columns are n/a.
  --local-cluster             derive RPC/metrics/pids from run/cluster (N=4
                              layout: rpc 18646, metrics 18081). --rpc may be
                              omitted; if given it is still guarded.
  --cpu-pids 1,2,3            fallback CPU source: sum /proc/<pid> CPU and
                              divide by the cell's finalized-block delta.
  --allow-remote              permit a non-loopback test endpoint
  --allow-validator-mismatch  do not refuse when stell_getValidators != N
  --allow-floor-mismatch      do not refuse when the local node env disagrees

LOAD
  --rates 100,1000,5000       offered tx/s list (default 100,1000,5000)
  --senders 128               sender threads for every cell (funded once)
  --duration 60               sending window per cell, seconds
  --drain-timeout 180         post-window drain budget per cell, seconds
  --settle 30                 quiet time between cells, seconds
  --per-cell-timeout 0        hard seconds per cell; 0 = duration+drain+120
  --max-429-share 0.01        above this share the cell is INVALID (429 storm)

MATRIX / RESULTS
  --matrix-n 4,32,128         rows to render even when not provisioned
  --matrix-floors 400,250     floors to render even when not provisioned
  --out DIR                   results dir (default run/perf-matrix/<UTC stamp>)
  --reuse                     keep existing measured cells (default)
  --force                     re-run cells even when a result exists
  --plan                      print the intended rows and exit
  --render-only DIR           re-render DIR/summary.md from saved cells

HARNESS
  --harness PATH              loadtest binary
  --build                     cargo build --release --offline before running

EXAMPLES
  # 4-validator local cluster, 400 ms floor (export propagates to each node)
  STELL_MIN_BLOCK_MS=400 ./scripts/local-cluster.sh up 4
  scripts/perf-matrix.sh --local-cluster --validators 4 \
    --block-floor-ms 400 --i-know-this-is-not-mainnet

  # same results set, second cluster
  scripts/perf-matrix.sh --rpc http://127.0.0.1:19646 \
    --metrics-url http://127.0.0.1:19081/metrics \
    --validators 32 --block-floor-ms 250 \
    --i-know-this-is-not-mainnet \
    --out run/perf-matrix/20260101T000000Z --reuse
EOF
}

say()  { printf 'perf-matrix: %s\n' "$*"; }
warn() { printf 'perf-matrix: WARN: %s\n' "$*" >&2; }
die()  { printf 'perf-matrix: FATAL: %s\n' "$*" >&2; exit 2; }

need_val() {
  if (( $# < 2 )) || [[ -z "${2:-}" ]]; then
    die "$1 requires a value"
  fi
}

# --- parsing -----------------------------------------------------------------
while (( $# > 0 )); do
  case "$1" in
    --rpc)                need_val "$@"; RPC="$2"; shift 2 ;;
    --metrics-url)        need_val "$@"; METRICS_URL="$2"; shift 2 ;;
    --validators)         need_val "$@"; VALIDATORS="$2"; shift 2 ;;
    --block-floor-ms)     need_val "$@"; BLOCK_FLOOR_MS="$2"; shift 2 ;;
    --rates)              need_val "$@"; RATES="$2"; shift 2 ;;
    --matrix-n)           need_val "$@"; MATRIX_NS="$2"; shift 2 ;;
    --matrix-floors)      need_val "$@"; MATRIX_FLOORS="$2"; shift 2 ;;
    --senders)            need_val "$@"; SENDERS="$2"; shift 2 ;;
    --duration)           need_val "$@"; DURATION="$2"; shift 2 ;;
    --drain-timeout)      need_val "$@"; DRAIN_TIMEOUT="$2"; shift 2 ;;
    --settle)             need_val "$@"; SETTLE="$2"; shift 2 ;;
    --per-cell-timeout)   need_val "$@"; PER_CELL_TIMEOUT="$2"; shift 2 ;;
    --max-429-share)      need_val "$@"; MAX_429_SHARE="$2"; shift 2 ;;
    --out)                need_val "$@"; OUT="$2"; shift 2 ;;
    --cpu-pids)           need_val "$@"; CPU_PIDS="$2"; shift 2 ;;
    --harness)            need_val "$@"; HARNESS="$2"; shift 2 ;;
    --render-only)        need_val "$@"; RENDER_ONLY="$2"; shift 2 ;;
    --local-cluster)      LOCAL_CLUSTER=1; shift ;;
    --allow-remote)       ALLOW_REMOTE=1; shift ;;
    --allow-validator-mismatch) ALLOW_VALIDATOR_MISMATCH=1; shift ;;
    --allow-floor-mismatch)     ALLOW_FLOOR_MISMATCH=1; shift ;;
    --i-know-this-is-not-mainnet) ACK=1; shift ;;
    --reuse)              REUSE=1; shift ;;
    --force)              FORCE=1; REUSE=0; shift ;;
    --plan)               PLAN=1; shift ;;
    --build)              BUILD=1; shift ;;
    -h|--help)            usage; exit 0 ;;
    *)                    die "unknown argument: $1 (see --help)" ;;
  esac
done

# --- render-only path is handled after the renderer is defined ---------------

# --- host/URL helpers --------------------------------------------------------
url_host() {
  local url="$1" rest authority host
  rest="${url#*://}"
  authority="${rest%%[/?#]*}"
  authority="${authority##*@}"
  if [[ "$authority" == \[* ]]; then
    host="${authority#\[}"
    host="${host%%\]*}"
  elif [[ "$authority" =~ ^(.*):([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
  else
    host="$authority"
  fi
  host="${host%.}"
  printf '%s' "${host,,}"
}

host_is_public() {
  local host="$1" h
  for h in "${PUBLIC_HOSTS[@]}"; do
    [[ "$host" == "$h" ]] && return 0
  done
  return 1
}

host_is_loopback() {
  local host="$1"
  case "$host" in
    localhost|::1|0:0:0:0:0:0:0:1) return 0 ;;
  esac
  [[ "$host" =~ ^127\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

guard_url() {
  local label="$1" url="$2" host
  [[ -n "$url" ]] || die "$label is empty"
  host="$(url_host "$url")"
  [[ -n "$host" ]] || die "$label has no host: $url"
  if host_is_public "$host"; then
    die "$label points at a known public/validator host ($host). Load is forbidden there."
  fi
  if ! host_is_loopback "$host" && (( ALLOW_REMOTE != 1 )); then
    die "$label ($host) is not loopback; pass --allow-remote for a TEST node"
  fi
}

# --- numeric validation ------------------------------------------------------
is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }
is_csv_uint() { [[ "$1" =~ ^[0-9]+(,[0-9]+)*$ ]]; }

normalize_csv() {
  local csv="$1" out="" part
  local -a parts
  IFS=',' read -r -a parts <<< "$csv"
  for part in "${parts[@]}"; do
    out="${out:+$out,}$((10#$part))"
  done
  printf '%s' "$out"
}

# --- local-cluster derivation ------------------------------------------------
derive_local_cluster() {
  RPC="${RPC:-http://127.0.0.1:18646}"
  METRICS_URL="${METRICS_URL:-http://127.0.0.1:18081/metrics}"
  if [[ -z "$CPU_PIDS" ]]; then
    local pids="" pidf pid
    for pidf in "$ROOT"/run/cluster/node*/node.pid; do
      [[ -f "$pidf" ]] || continue
      pid="$(cat "$pidf" 2>/dev/null || true)"
      is_uint "$pid" || continue
      pids="${pids:+$pids,}$pid"
    done
    CPU_PIDS="$pids"
  fi
  if [[ -n "$CPU_PIDS" ]] && ! host_is_loopback "$(url_host "$RPC")"; then
    warn "ignoring local-cluster CPU pids: --rpc is not loopback"
    CPU_PIDS=""
  fi
}

# --- floor verification ------------------------------------------------------
# Ask the running local node's environment what floor it actually uses. When
# the variable is absent the compiled default (50 ms) applies. Every node must
# agree; a disagreement means the "floor" label would be fiction.
local_floor_ms() {
  local pidf pid envline floor="" seen=""
  for pidf in "$ROOT"/run/cluster/node*/node.pid; do
    [[ -f "$pidf" ]] || continue
    pid="$(cat "$pidf" 2>/dev/null || true)"
    [[ -r "/proc/$pid/environ" ]] || continue
    envline="$(tr '\0' '\n' < "/proc/$pid/environ" | grep -m1 '^STELL_MIN_BLOCK_MS=' || true)"
    if [[ -n "$envline" ]]; then
      floor="${envline#*=}"
    else
      floor="50"
    fi
    if [[ -z "$seen" ]]; then
      seen="$floor"
    elif [[ "$seen" != "$floor" ]]; then
      warn "local nodes disagree on STELL_MIN_BLOCK_MS ($seen vs $floor); floor is not verifiable"
      return 1
    fi
  done
  [[ -n "$seen" ]] || return 1
  printf '%s' "$seen"
}

verify_declared_floor() {
  (( LOCAL_CLUSTER == 1 )) || return 0
  local actual
  if ! actual="$(local_floor_ms)"; then
    warn "could not verify STELL_MIN_BLOCK_MS from running local nodes; recording the declared value"
    return 0
  fi
  if [[ "$actual" != "$BLOCK_FLOOR_MS" ]]; then
    if (( ALLOW_FLOOR_MISMATCH == 1 )); then
      warn "declared floor ${BLOCK_FLOOR_MS} ms but local nodes run ${actual} ms (overridden)"
      return 0
    else
      die "declared --block-floor-ms ${BLOCK_FLOOR_MS} but local nodes run ${actual} ms; \
fix the cluster or pass --allow-floor-mismatch"
    fi
  fi
  FLOOR_VERIFIED=1
}

# --- host / meta -------------------------------------------------------------
utc_now() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

host_model() {
  awk -F': ' '/^model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null || true
}

write_meta() {
  local commit dirty_count dirty model nproc mem_kib kernel harness_sha
  commit="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  dirty_count="$(git -C "$ROOT" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$dirty_count" == "0" ]]; then dirty="false"; else dirty="true"; fi
  model="$(host_model)"
  [[ -n "$model" ]] || model="unknown"
  nproc="$(nproc 2>/dev/null || printf '0')"
  mem_kib="$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null || printf '0')"
  kernel="$(uname -srm 2>/dev/null || printf 'unknown')"
  harness_sha="$(sha256sum "$HARNESS" 2>/dev/null | awk '{print $1}' || true)"
  [[ -n "$harness_sha" ]] || harness_sha="unknown"

  jq -n \
    --arg generated_utc "$(utc_now)" \
    --arg commit "$commit" \
    --argjson dirty "$dirty" \
    --argjson dirty_files "${dirty_count:-0}" \
    --arg repo "$ROOT" \
    --arg kernel "$kernel" \
    --arg model "$model" \
    --argjson nproc "${nproc:-0}" \
    --argjson mem_kib "${mem_kib:-0}" \
    --arg harness "$HARNESS" \
    --arg harness_sha256 "$harness_sha" \
    --arg rpc "$RPC" \
    --arg metrics_url "$METRICS_URL" \
    --argjson validators "$VALIDATORS" \
    --argjson block_floor_ms "$BLOCK_FLOOR_MS" \
    --argjson floor_verified "$FLOOR_VERIFIED" \
    --arg rates "$RATES" \
    --arg matrix_ns "$MATRIX_NS" \
    --arg matrix_floors "$MATRIX_FLOORS" \
    --argjson settle_s "$SETTLE" \
    --arg max_429_share "$MAX_429_SHARE" \
    --argjson senders "$SENDERS" \
    --argjson duration_s "$DURATION" \
    --argjson allow_remote "$ALLOW_REMOTE" \
    --arg bash_version "${BASH_VERSION:-unknown}" \
    --arg jq_version "$(jq --version 2>/dev/null || printf 'unknown')" \
    --arg cmdline "scripts/perf-matrix.sh $(printf '%q ' "${ORIG_ARGS[@]}")" \
    '{generated_utc:$generated_utc, commit:$commit, dirty:$dirty,
      dirty_files:$dirty_files, repo:$repo,
      host:{kernel:$kernel, model:$model, nproc:$nproc, mem_kib:$mem_kib},
      harness:{path:$harness, sha256:$harness_sha256},
      rpc:$rpc, metrics_url:$metrics_url,
      allow_remote:$allow_remote,
      declared:{validators:$validators, block_floor_ms:$block_floor_ms,
                floor_verified:$floor_verified, rates:$rates,
                matrix_ns:$matrix_ns, matrix_floors:$matrix_floors,
                settle_s:$settle_s, max_429_share:$max_429_share,
                senders:$senders, duration_s:$duration_s},
      tooling:{bash:$bash_version, jq:$jq_version},
      cmdline:$cmdline}' > "$OUT/meta.json"
}

# --- RPC / metrics -----------------------------------------------------------
rpc_call() {
  local method="$1" params="${2:-[]}"
  curl -fsS --max-time 10 \
    -H 'content-type: application/json' \
    --data-binary "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" \
    "$RPC"
}

rpc_height() {
  local h
  h="$(rpc_call stell_blockNumber | jq -r '.result // empty' 2>/dev/null || true)"
  if [[ -z "$h" ]]; then printf '0'; return; fi
  if [[ "$h" == 0x* || "$h" == 0X* ]]; then
    printf '%d' "$h" 2>/dev/null || printf '0'
  elif is_uint "$h"; then
    printf '%s' "$h"
  else
    printf '0'
  fi
}

snap_metrics() {
  local file="$1"
  [[ -n "$METRICS_URL" ]] || return 1
  curl -fsS --max-time 10 "$METRICS_URL" -o "$file" 2>/dev/null
}

proc_cpu_ticks() {
  local pids="$1" total=0 pid t
  local -a list
  IFS=',' read -r -a list <<< "$pids"
  for pid in "${list[@]}"; do
    is_uint "$pid" || continue
    [[ -r "/proc/$pid/stat" ]] || continue
    # Drop "pid (comm) " (comm may contain spaces/parens), then fields 12/13
    # after it are utime/stime in clock ticks.
    t="$(awk '{ sub(/^.*\) /, ""); print $12+$13 }' "/proc/$pid/stat" 2>/dev/null || printf '0')"
    is_uint "$t" || t=0
    total=$(( total + t ))
  done
  printf '%s' "$total"
}

# --- harness -----------------------------------------------------------------
ensure_harness() {
  if (( BUILD == 1 )); then
    say "building harness: cargo build --release --offline"
    cargo build --release --offline --manifest-path "$HARNESS_MANIFEST" \
      || die "harness build failed"
  fi
  [[ -x "$HARNESS" ]] || die "harness not executable: $HARNESS (build it or pass --build)"
  "$HARNESS" --help >/dev/null 2>&1 \
    || die "harness does not answer --help: $HARNESS"
  if ! grep -aq 'confirmation_latency_s' "$HARNESS" 2>/dev/null; then
    warn "this harness binary predates the confirmation_latency_s field; \
every cell will report confirmation n/a. Rebuild scripts/loadtest/loadtest (--build)."
  fi
}

# --- cell records ------------------------------------------------------------
json_or_null() {
  # json_or_null FILE FILTER -> compact JSON value, `null` on any failure.
  local file="$1" filter="$2" out
  out="$(jq -c "$filter // null" "$file" 2>/dev/null || true)"
  [[ -n "$out" ]] || out="null"
  printf '%s' "$out"
}

record_blocked_all() {
  local reason="$1" rate
  IFS=',' read -r -a _rates <<< "$RATES"
  for rate in "${_rates[@]}"; do
    write_cell "$VALIDATORS" "$BLOCK_FLOOR_MS" "$rate" "blocked" "$reason" "$reason" \
      "null" "null" "null" "null" "null" \
      "null" "null" "null" \
      "null" "null" "null" "null" \
      "null" "null" \
      "null" "n/a" "null" "null" "null"
  done
}

# write_cell N FLOOR RATE STATUS REASON NOTES
#   ACCEPTED INCLUDED SUBMITTED FAILED HTTP429 APPLY_P50 APPLY_P95 APPLY_P99
#   CONF_P50 CONF_P95 CONF_P99 CONF_N BLOCK_P50 BLOCK_P95 CPU BLOCK_SRC
#   FAILED_SHARE REJECTED_SHARE HEIGHT_DELTA
write_cell() {
  if (( $# != 25 )); then
    die "internal: write_cell expects 25 arguments, got $#"
  fi
  local n="$1" floor="$2" rate="$3" status="$4" reason="$5" notes="$6"
  local accepted="$7" included="$8" submitted="$9" failed="${10}"
  local http429="${11}" ap50="${12}" ap95="${13}" ap99="${14}"
  local cp50="${15}" cp95="${16}" cp99="${17}" cn="${18}"
  local bp50="${19}" bp95="${20}" cpu="${21}" block_src="${22}"
  local fshare="${23}" rshare="${24}" hdelta="${25}"
  local id="n${n}-f${floor}-r${rate}"
  local dir="$OUT/cells/$id"
  mkdir -p "$dir"
  jq -n \
    --arg id "$id" \
    --argjson n "$n" \
    --argjson block_floor_ms "$floor" \
    --argjson offered_tps "$rate" \
    --argjson senders "$SENDERS" \
    --arg status "$status" \
    --arg reason "$reason" \
    --arg notes "$notes" \
    --arg rpc "$RPC" \
    --arg metrics_url "$METRICS_URL" \
    --arg chain_id "$CHAIN_ID" \
    --argjson accepted_tps "$accepted" \
    --argjson included_tps "$included" \
    --argjson submitted "$submitted" \
    --argjson failed "$failed" \
    --argjson http_429 "$http429" \
    --argjson apply_p50 "$ap50" \
    --argjson apply_p95 "$ap95" \
    --argjson apply_p99 "$ap99" \
    --argjson confirm_p50 "$cp50" \
    --argjson confirm_p95 "$cp95" \
    --argjson confirm_p99 "$cp99" \
    --argjson confirm_n "$cn" \
    --argjson block_p50 "$bp50" \
    --argjson block_p95 "$bp95" \
    --argjson cpu_per_block "$cpu" \
    --arg block_src "$block_src" \
    --argjson receipt_failed_share "$fshare" \
    --argjson rejected_share "$rshare" \
    --argjson height_delta "$hdelta" \
    '{id:$id, n:$n, block_floor_ms:$block_floor_ms, offered_tps:$offered_tps,
      senders:$senders, status:$status, reason:$reason, notes:$notes,
      accepted_tps:$accepted_tps, included_tps:$included_tps,
      submitted:$submitted, failed:$failed, http_429:$http_429,
      apply:{p50:$apply_p50,p95:$apply_p95,p99:$apply_p99},
      confirmation:{p50:$confirm_p50,p95:$confirm_p95,p99:$confirm_p99,n:$confirm_n},
      block:{p50:$block_p50,p95:$block_p95,src:$block_src},
      cpu_per_block:$cpu_per_block,
      receipt:{failed_share:$receipt_failed_share},
      rejected_share:$rejected_share, height_delta:$height_delta,
      rpc:$rpc, metrics_url:$metrics_url, chain_id:$chain_id}' > "$dir/cell.json"
}

# --- preflight ---------------------------------------------------------------
preflight_funding() {
  local log="$OUT/preflight.log" rc
  local -a cmd=("$HARNESS" --allow-live --url "$RPC" --senders "$SENDERS" --preflight-only)
  if (( ALLOW_REMOTE == 1 )); then cmd+=(--allow-remote); fi
  timeout --signal=INT --kill-after=30s 300s "${cmd[@]}" > "$log" 2>&1
  rc=$?
  if (( rc == 0 )); then
    say "preflight: $SENDERS senders funded and ready"
    return 0
  fi
  if (( rc == 3 )); then
    local roster="$OUT/senders.txt"
    local -a print_cmd=("$HARNESS" --allow-live --url "$RPC" --senders "$SENDERS" --print-all-senders)
    if (( ALLOW_REMOTE == 1 )); then print_cmd+=(--allow-remote); fi
    timeout --signal=INT --kill-after=30s 300s "${print_cmd[@]}" > "$roster" 2>&1 || true
    warn "sender set is unfunded; roster written to $roster"
    return 3
  fi
  warn "preflight failed with exit $rc; see $log"
  return "$rc"
}

# --- one cell ----------------------------------------------------------------
run_cell() {
  local n="$1" floor="$2" rate="$3"
  local id="n${n}-f${floor}-r${rate}"
  local dir="$OUT/cells/$id"
  mkdir -p "$dir"

  if [[ -f "$dir/cell.json" ]] && (( REUSE == 1 )) && (( FORCE != 1 )); then
    local prev
    prev="$(jq -r '.status // ""' "$dir/cell.json" 2>/dev/null || true)"
    if [[ "$prev" == "measured" || "$prev" == "invalid-429" || "$prev" == "measured-fail" ]]; then
      say "skip $id (already $prev; --force to re-run)"
      return 0
    fi
  fi

  # A failed prior attempt must not leave stale evidence behind.
  rm -f "$dir/report.json" "$dir/metrics-before.txt" "$dir/metrics-after.txt" \
        "$dir/metrics-delta.json" "$dir/metrics-delta.err" \
        "$dir/cpu-before.txt" "$dir/cpu-after.txt"

  local hard="$PER_CELL_TIMEOUT"
  if (( hard <= 0 )); then
    hard=$(( DURATION + DRAIN_TIMEOUT + 120 ))
  fi

  say "cell $id: offered ${rate} tx/s, ${SENDERS} senders, ${DURATION}s, floor ${floor} ms, timeout ${hard}s"

  local -a cmd=("$HARNESS" --allow-live --url "$RPC" --watch-url "$RPC"
    --senders "$SENDERS" --rate "$rate" --duration "$DURATION"
    --drain-timeout "$DRAIN_TIMEOUT" --stall-seconds 30 --max-lag-blocks 500
    --json-out "$dir/report.json")
  if (( ALLOW_REMOTE == 1 )); then cmd+=(--allow-remote); fi
  if [[ -n "$METRICS_URL" ]]; then cmd+=(--metrics-url "$METRICS_URL"); fi
  { printf '%q ' "${cmd[@]}"; printf '\n'; } > "$dir/command.txt"

  local have_metrics=0 have_cpu=0
  local height_before height_after
  height_before="$(rpc_height)"
  if snap_metrics "$dir/metrics-before.txt" && [[ -s "$dir/metrics-before.txt" ]]; then
    have_metrics=1
  fi
  if [[ -n "$CPU_PIDS" ]]; then
    proc_cpu_ticks "$CPU_PIDS" > "$dir/cpu-before.txt"
    have_cpu=1
  fi

  local rc
  set +e
  timeout --signal=INT --kill-after=30s "${hard}s" "${cmd[@]}" \
    > "$dir/loadtest.log" 2>&1
  rc=$?
  set -e

  height_after="$(rpc_height)"
  if (( have_metrics == 1 )); then
    if ! snap_metrics "$dir/metrics-after.txt" || [[ ! -s "$dir/metrics-after.txt" ]]; then
      warn "$id: metrics-after scrape failed or was empty; metrics columns will be n/a"
      have_metrics=0
    fi
  fi
  if (( have_cpu == 1 )); then
    proc_cpu_ticks "$CPU_PIDS" > "$dir/cpu-after.txt"
  fi

  local delta_ok=0
  if (( have_metrics == 1 )); then
    if awk -f "$DELTA_AWK" "$dir/metrics-before.txt" "$dir/metrics-after.txt" \
        > "$dir/metrics-delta.json" 2> "$dir/metrics-delta.err"; then
      delta_ok=1
    else
      warn "$id: metrics delta failed (counter reset or malformed scrape); see metrics-delta.err"
    fi
  fi

  local status reason=""
  local notes=""
  case "$rc" in
    0)   status="measured" ;;
    1)   status="measured-fail"; reason="harness verdict FAIL" ;;
    2)   status="blocked"; reason="harness refused to run (safety/usage); see loadtest.log" ;;
    3)   status="blocked"; reason="harness preflight: sender underfunded" ;;
    4)   status="aborted"; reason="harness stop condition (stall/lag/backlog)" ;;
    124) status="timeout"; reason="hard timeout ${hard}s" ;;
    *)   status="failed"; reason="harness exit $rc" ;;
  esac
  [[ -n "$reason" ]] || reason=""

  if [[ ! -s "$dir/report.json" ]]; then
    if [[ "$status" == "measured" || "$status" == "measured-fail" ]]; then
      status="failed"
      reason="${reason:+$reason; }no JSON report written"
    fi
  fi

  local accepted="null" included="null" submitted="null" failed="null" http429="null"
  local ap50="null" ap95="null" ap99="null"
  local cp50="null" cp95="null" cp99="null" cn="null"
  local bp50="null" bp95="null" block_src="n/a"
  local fshare="null" rshare="null" hdelta="null"
  local cpu="null"

  if [[ -s "$dir/report.json" ]]; then
    accepted="$(json_or_null "$dir/report.json" '.rates.accepted_tps')"
    included="$(json_or_null "$dir/report.json" '.rates.included_tps')"
    submitted="$(json_or_null "$dir/report.json" '.counts.submitted')"
    failed="$(json_or_null "$dir/report.json" '.counts.failed')"
    http429="$(json_or_null "$dir/report.json" '.counts.http_429')"
    hdelta="$(json_or_null "$dir/report.json" '.height.delta')"
    rshare="$(json_or_null "$dir/report.json" '.rates.rejected_share')"
    fshare="$(json_or_null "$dir/report.json" \
      'if (.receipt_sample.queried // 0) > 0 then (.receipt_sample.failed / .receipt_sample.queried) else null end')"
    bp50="$(json_or_null "$dir/report.json" '.block_time_s.p50')"
    bp95="$(json_or_null "$dir/report.json" '.block_time_s.p95')"
    if [[ "$bp50" != "null" ]]; then block_src="harness observed arrival"; fi
    cp50="$(json_or_null "$dir/report.json" '.confirmation_latency_s.p50')"
    cp95="$(json_or_null "$dir/report.json" '.confirmation_latency_s.p95')"
    cp99="$(json_or_null "$dir/report.json" '.confirmation_latency_s.p99')"
    cn="$(json_or_null "$dir/report.json" '.confirmation_latency_s.n')"
    if [[ "$cp50" == "null" ]]; then
      notes="confirmation n/a (harness binary predates confirmation_latency_s)"
    fi
  fi

  if (( delta_ok == 1 )); then
    ap50="$(json_or_null "$dir/metrics-delta.json" '.apply.p50')"
    ap95="$(json_or_null "$dir/metrics-delta.json" '.apply.p95')"
    ap99="$(json_or_null "$dir/metrics-delta.json" '.apply.p99')"
    local mbp50 mbp95
    mbp50="$(json_or_null "$dir/metrics-delta.json" '.block_interval.p50')"
    mbp95="$(json_or_null "$dir/metrics-delta.json" '.block_interval.p95')"
    if [[ "$mbp50" != "null" ]]; then
      bp50="$mbp50"; bp95="$mbp95"; block_src="node stell_block_interval_seconds"
    fi
    cpu="$(json_or_null "$dir/metrics-delta.json" '.cpu_per_block.mean')"
  fi

  # Prefer the harness height delta; fall back to the RPC heights taken around
  # the cell so a missing/older JSON field cannot hide the CPU denominator.
  if [[ "$hdelta" == "null" ]] && is_uint "$height_before" && is_uint "$height_after" \
      && (( height_before > 0 && height_after >= height_before )); then
    hdelta=$(( height_after - height_before ))
  fi

  # /proc fallback for CPU when the node's histogram is unavailable.
  if [[ "$cpu" == "null" && -f "$dir/cpu-before.txt" && -f "$dir/cpu-after.txt" && "$hdelta" != "null" ]]; then
    local cb ca clk dticks blocks cpus
    cb="$(cat "$dir/cpu-before.txt")"
    ca="$(cat "$dir/cpu-after.txt")"
    clk="$(getconf CLK_TCK 2>/dev/null || printf '100')"
    is_uint "$cb" || cb=0
    is_uint "$ca" || ca=0
    is_uint "$hdelta" || hdelta=0
    if (( ca >= cb && hdelta > 0 && clk > 0 )); then
      dticks=$(( ca - cb ))
      blocks="$hdelta"
      cpus="$(awk -v t="$dticks" -v c="$clk" -v b="$blocks" 'BEGIN{printf "%.6f", (t/c)/b}')"
      cpu="$cpus"
      notes="${notes:+$notes; }CPU from host /proc (sum of ${CPU_PIDS}), not the node histogram"
    fi
  fi

  # 429 storm invalidates throughput; the numbers stay visible but flagged.
  if [[ "$status" == "measured" || "$status" == "measured-fail" ]]; then
    if [[ "$http429" != "null" && "$submitted" != "null" ]]; then
      local storm
      storm="$(awk -v e="$http429" -v s="$submitted" -v m="$MAX_429_SHARE" \
        'BEGIN{ if (s > 0 && (e/s) > m) print "1"; else print "0" }')"
      if [[ "$storm" == "1" ]]; then
        status="invalid-429"
        local pct
        pct="$(awk -v e="$http429" -v s="$submitted" 'BEGIN{printf "%.2f", 100*e/s}')"
        notes="${notes:+$notes; }429 storm ${pct}% > $(awk -v m="$MAX_429_SHARE" 'BEGIN{printf "%.2f",100*m}')%"
      fi
    fi
  fi

  # A measured cell below the offered rate cannot say whether the sender set or
  # the node bound it; say so instead of implying node capacity.
  if [[ "$accepted" != "null" && "$rate" -gt 0 ]]; then
    local ratio
    ratio="$(awk -v a="$accepted" -v r="$rate" 'BEGIN{ if (r>0) printf "%.3f", a/r; else print "1" }')"
    if awk -v x="$ratio" 'BEGIN{exit !(x < 0.75)}'; then
      notes="${notes:+$notes; }accepted < 75% of offered (sender and/or node bound)"
    fi
  fi
  case "$status" in
    blocked|failed|timeout|aborted) notes="${notes:+$notes; }${reason}" ;;
  esac

  write_cell "$n" "$floor" "$rate" "$status" "$reason" "$notes" \
    "$accepted" "$included" "$submitted" "$failed" "$http429" \
    "$ap50" "$ap95" "$ap99" "$cp50" "$cp95" "$cp99" "$cn" \
    "$bp50" "$bp95" "$cpu" "$block_src" "$fshare" "$rshare" "$hdelta"

  say "cell $id done: $status (exit $rc)"
}

# --- settle between cells ----------------------------------------------------
settle_between_cells() {
  (( SETTLE > 0 )) || return 0
  local deadline=$(( SECONDS + SETTLE ))
  say "settling up to ${SETTLE}s (height must advance, mempool must be 0)"
  while (( SECONDS < deadline )); do
    local h1 h2 m
    h1="$(rpc_height)"
    sleep 2
    h2="$(rpc_height)"
    m="$(rpc_call stell_mempoolSize 2>/dev/null | jq -r '.result // empty' 2>/dev/null || true)"
    if (( h2 > h1 )) && [[ "$m" == "0" ]]; then
      return 0
    fi
    sleep 2
  done
  warn "settle window elapsed without height growth + empty mempool; the next cell may inherit load"
}

# --- rendering ---------------------------------------------------------------
fmt2() {
  local v="$1"
  [[ "$v" == "null" || -z "$v" ]] && { printf 'n/a'; return; }
  awk -v x="$v" 'BEGIN{printf "%.2f", x}'
}

fmt_ms() {
  local v="$1"
  [[ "$v" == "null" || -z "$v" ]] && { printf 'n/a'; return; }
  if [[ "$v" == \>=* ]]; then
    local x="${v#>=}"
    printf '>=%s' "$(awk -v x="$x" 'BEGIN{printf "%.1f", x*1000}')"
  else
    awk -v x="$v" 'BEGIN{printf "%.1f", x*1000}'
  fi
}

fmt_pct() {
  local v="$1"
  [[ "$v" == "null" || -z "$v" ]] && { printf 'n/a'; return; }
  awk -v x="$v" 'BEGIN{printf "%.2f%%", 100*x}'
}

fmt_ms3() {
  local v="$1"
  [[ "$v" == "null" || -z "$v" ]] && { printf 'n/a'; return; }
  awk -v x="$v" 'BEGIN{printf "%.3f", x}'
}

# Collect every saved cell into ordered dimension lists.
build_render_lists() {
  local -a obs_n=() obs_f=() obs_r=() canon_n=() canon_f=() canon_r=()
  IFS=',' read -r -a canon_n <<< "$MATRIX_NS"
  IFS=',' read -r -a canon_f <<< "$MATRIX_FLOORS"
  IFS=',' read -r -a canon_r <<< "$RATES"
  if compgen -G "$OUT/cells/*/cell.json" > /dev/null; then
    mapfile -t obs_n < <(jq -r '.n' "$OUT"/cells/*/cell.json 2>/dev/null | sort -n -u)
    mapfile -t obs_f < <(jq -r '.block_floor_ms' "$OUT"/cells/*/cell.json 2>/dev/null | sort -n -u)
    mapfile -t obs_r < <(jq -r '.offered_tps' "$OUT"/cells/*/cell.json 2>/dev/null | sort -n -u)
  fi
  mapfile -t RENDER_NS < <(printf '%s\n' "${canon_n[@]}" "${obs_n[@]}" | sed '/^$/d' | sort -n -u)
  mapfile -t RENDER_RS < <(printf '%s\n' "${canon_r[@]}" "${obs_r[@]}" | sed '/^$/d' | sort -n -u)
  mapfile -t RENDER_FS < <(printf '%s\n' "${canon_f[@]}" "${obs_f[@]}" | sed '/^$/d' | sort -n -ru)
}

cluster_present() {
  local n="$1" f="$2" file
  compgen -G "$OUT/cells/*/cell.json" > /dev/null || return 1
  for file in "$OUT"/cells/*/cell.json; do
    [[ -f "$file" ]] || continue
    if [[ "$(jq -r '.n' "$file" 2>/dev/null)" == "$n" &&
          "$(jq -r '.block_floor_ms' "$file" 2>/dev/null)" == "$f" ]]; then
      return 0
    fi
  done
  return 1
}

render_row() {
  local n="$1" floor="$2" rate="$3"
  local id="n${n}-f${floor}-r${rate}"
  local file="$OUT/cells/$id/cell.json"
  local state accepted included apply conf block cpu fshare notes
  if [[ ! -f "$file" ]]; then
    local why
    if cluster_present "$n" "$floor"; then
      why="rate ${rate} was not in this run's --rates list (re-run with --reuse to add it)"
    elif (( n >= 32 )); then
      why="cluster N=$n @ ${floor} ms was not provisioned in this results set (run against that cluster with --reuse; a single host hosting $n validators is not assumed honest)"
    else
      why="no cluster with N=$n at ${floor} ms in this results set (re-run the matrix on that cluster with --reuse)"
    fi
    printf '| %s | %s | %s | %s | **NOT MEASURED** | — | — | — | — | — | — | — | %s |\n' \
      "$n" "$floor" "$rate" "$SENDERS" "$why"
    return
  fi

  state="$(jq -r '.status' "$file")"
  accepted="$(fmt2 "$(jq -r '.accepted_tps' "$file")")"
  included="$(fmt2 "$(jq -r '.included_tps' "$file")")"
  apply="$(fmt_ms "$(jq -r '.apply.p50' "$file")")/$(fmt_ms "$(jq -r '.apply.p95' "$file")")/$(fmt_ms "$(jq -r '.apply.p99' "$file")")"
  conf="$(fmt_ms "$(jq -r '.confirmation.p50' "$file")")/$(fmt_ms "$(jq -r '.confirmation.p95' "$file")")/$(fmt_ms "$(jq -r '.confirmation.p99' "$file")")"
  block="$(fmt_ms "$(jq -r '.block.p50' "$file")")/$(fmt_ms "$(jq -r '.block.p95' "$file")")"
  cpu="$(fmt_ms3 "$(jq -r '.cpu_per_block' "$file")")"
  fshare="$(fmt_pct "$(jq -r '.receipt.failed_share' "$file")")"
  notes="$(jq -r '.notes // ""' "$file")"
  case "$state" in
    measured)       state="measured" ;;
    measured-fail)  state="measured (FAIL)" ;;
    invalid-429)    state="**INVALID** (429)" ;;
    aborted)        state="ABORTED" ;;
    timeout)        state="TIMEOUT" ;;
    blocked)        state="BLOCKED" ;;
    failed)         state="FAILED" ;;
    *)              state="**${state^^}**" ;;
  esac
  printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
    "$n" "$floor" "$rate" "$SENDERS" "$state" "$accepted" "$included" \
    "$apply" "$conf" "$block" "$cpu" "$fshare" "${notes:-—}"
}

command_appendix() {
  local file id
  printf '## Appendix A — exact per-cell commands\n\n'
  printf 'Each line is the argv saved in `cells/<id>/command.txt`.\n\n'
  printf '```bash\n'
  for file in "$OUT"/cells/*/command.txt; do
    [[ -f "$file" ]] || continue
    id="$(basename "$(dirname "$file")")"
    printf '# %s\n' "$id"
    cat "$file"
  done
  printf '```\n\n'
}

render_summary() {
  [[ -d "$OUT" ]] || return 0
  build_render_lists
  local meta="$OUT/meta.json"
  local ts commit dirty host_nproc host_mem host_model kernel harness_sha cmdline rpc metrics
  ts="$(jq -r '.generated_utc // "unknown"' "$meta" 2>/dev/null || printf 'unknown')"
  commit="$(jq -r '.commit // "unknown"' "$meta" 2>/dev/null || printf 'unknown')"
  dirty="$(jq -r 'if .dirty then "dirty working tree (" + (.dirty_files|tostring) + " changed files)" else "clean" end' "$meta" 2>/dev/null || printf 'unknown')"
  host_nproc="$(jq -r '.host.nproc // 0' "$meta" 2>/dev/null || printf '0')"
  host_mem="$(jq -r '.host.mem_kib // 0' "$meta" 2>/dev/null || printf '0')"
  host_model="$(jq -r '.host.model // "unknown"' "$meta" 2>/dev/null || printf 'unknown')"
  kernel="$(jq -r '.host.kernel // "unknown"' "$meta" 2>/dev/null || printf 'unknown')"
  harness_sha="$(jq -r '.harness.sha256 // "unknown"' "$meta" 2>/dev/null || printf 'unknown')"
  rpc="$(jq -r '.rpc // "unknown"' "$meta" 2>/dev/null || printf 'unknown')"
  metrics="$(jq -r '.metrics_url // ""' "$meta" 2>/dev/null || true)"
  cmdline="$(jq -r '.cmdline // "unknown"' "$meta" 2>/dev/null || printf 'unknown')"

  {
    printf '# Stellereum throughput/latency matrix\n\n'
    printf '> Generated by `scripts/perf-matrix.sh` on %s. Every row is an\n' "$ts"
    printf '> independent 1-cell-at-a-time load wave. `NOT MEASURED` is deliberate:\n'
    printf '> this report never infers a number for a cell that was not run.\n\n'

    printf '## How to reproduce\n\n'
    printf -- '- **Repo**: `%s`\n' "$(jq -r '.repo // "unknown"' "$meta" 2>/dev/null || printf 'unknown')"
    printf -- '- **Commit**: `%s` (%s)\n' "$commit" "$dirty"
    printf -- '- **Date (UTC)**: %s\n' "$ts"
    printf -- '- **Host**: %s; %s vCPU; %s KiB RAM; `%s`\n' \
      "$host_model" "$host_nproc" "$host_mem" "$kernel"
    printf -- '- **Harness**: `%s` sha256 `%s`\n' \
      "$(jq -r '.harness.path // "unknown"' "$meta" 2>/dev/null || printf 'unknown')" "$harness_sha"
    printf -- '- **RPC (last invocation)**: `%s`\n' "$rpc"
    if [[ -n "$metrics" && "$metrics" != "null" ]]; then
      printf -- '- **Node metrics (last invocation)**: `%s`\n' "$metrics"
    else
      printf -- '- **Node metrics (last invocation)**: none supplied (apply/CPU columns are `n/a`)\n'
    fi
    if [[ "$(jq -r '.declared.floor_verified // 0' "$meta" 2>/dev/null || printf '0')" == "1" ]]; then
      printf -- '- **Block floor**: %s ms, verified from the running local node environment\n' \
        "$(jq -r '.declared.block_floor_ms // 0' "$meta" 2>/dev/null || printf '0')"
    else
      printf -- '- **Block floor (declared)**: %s ms; not verifiable over RPC (see docs/PERF_MATRIX.md §6)\n' \
        "$(jq -r '.declared.block_floor_ms // 0' "$meta" 2>/dev/null || printf '0')"
    fi
    printf -- '- **Invocation**: `%s`\n' "$cmdline"
    printf -- '- **Prerequisites**: harness built; deterministic senders funded; node RPC limiter above the offered rate+reads; one cell at a time.\n'
    printf -- '- **Raw evidence**: `meta.json`, `cells/*/` (command, log, JSON, scrapes), `matrix.jsonl`.\n\n'

    printf '**Recipe** (adapt step 2 to the cluster you actually provisioned; the\n'
    printf 'recorded invocation below is the exact one that produced these cells):\n\n'
    printf '```bash\n'
    printf 'cd %s\n' "$(jq -r '.repo // "."' "$meta" 2>/dev/null || printf '.')"
    printf 'cargo build --release --offline --manifest-path scripts/loadtest/loadtest/Cargo.toml\n'
    printf '# 2. provision the cluster; for the local layout only:\n'
    printf '#    STELL_MIN_BLOCK_MS=%s ./scripts/local-cluster.sh up %s\n' \
      "$(jq -r '.declared.block_floor_ms // "MS"' "$meta" 2>/dev/null || printf 'MS')" \
      "$(jq -r '.declared.validators // "N"' "$meta" 2>/dev/null || printf 'N')"
    local remote_flag=""
    if [[ "$(jq -r '.allow_remote // false' "$meta" 2>/dev/null || printf 'false')" == "true" ]]; then
      remote_flag=" --allow-remote"
    fi
    printf '# 3. print the deterministic sender roster, fund it once, then:\n'
    printf '%q --allow-live%s --url %q --senders %s --print-all-senders\n' \
      "$(jq -r '.harness.path // "stell-loadtest"' "$meta" 2>/dev/null || printf 'stell-loadtest')" \
      "$remote_flag" "$rpc" \
      "$(jq -r '.declared.senders // 0' "$meta" 2>/dev/null || printf '0')"
    printf '%s\n' "$cmdline"
    printf '# 4. re-render without re-running:\n'
    printf 'scripts/perf-matrix.sh --render-only %q\n' "$OUT"
    printf '```\n\n'

    printf '## Provisioned clusters in this results set\n\n'
    printf '| N | floor ms | RPC |\n'
    printf '|---:|---:|---|\n'
    if compgen -G "$OUT/cells/*/cell.json" > /dev/null; then
      jq -r '[.n,.block_floor_ms,.rpc] | @tsv' \
        "$OUT"/cells/*/cell.json 2>/dev/null \
        | sort -u \
        | while IFS=$'\t' read -r cn cf cr; do
            printf '| %s | %s | `%s` |\n' "$cn" "$cf" "$cr"
          done
    else
      printf '| — | — | — |\n'
    fi
    printf '\n'

    printf '## Matrix\n\n'
    printf '| N | floor ms | offered tx/s | senders | state | accepted tx/s | included tx/s | apply p50/p95/p99 ms | confirm p50/p95/p99 ms | block p50/p95 ms | CPU s/block | reverted sample | notes |\n'
    printf '|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---|\n'
    local n f r
    for n in "${RENDER_NS[@]}"; do
      for f in "${RENDER_FS[@]}"; do
        for r in "${RENDER_RS[@]}"; do
          render_row "$n" "$f" "$r"
        done
      done
    done
    printf '\n'
    printf '`apply` = node `stell_apply_seconds` (delta, bucket-interpolated). '
    printf '`confirm` = harness submit-to-on-chain-nonce latency. '
    printf '`block` = node `stell_block_interval_seconds` when available, else the harness observed arrival. '
    printf '`CPU` = node `stell_cpu_per_block_seconds` mean, else host `/proc` fallback (noted). '
    printf '`>=` means the quantile fell in the `+Inf` bucket and is censored, not a point value.\n\n'
    printf 'The metric window brackets the whole harness invocation (preflight + start delay). '
    printf 'Histograms come from the single node behind `--metrics-url`; they are not a cluster aggregate.\n\n'

    printf '## Metric provenance\n\n'
    printf '| column | source | caveat |\n'
    printf '|---|---|---|\n'
    printf '| accepted tx/s | harness `rates.accepted_tps` | mempool acceptance, not execution |\n'
    printf '| included tx/s | harness on-chain nonce delta / send window | authoritative inclusion count |\n'
    printf '| apply p50/p95/p99 | `stell_apply_seconds` histogram delta | bucket resolution; `+Inf` is censored |\n'
    printf '| confirm p50/p95/p99 | harness `confirmation_latency_s` | poll-cadence resolution, inclusion not finality |\n'
    printf '| block p50/p95 | `stell_block_interval_seconds` or harness arrival | node histogram is finalized intervals |\n'
    printf '| CPU s/block | `stell_cpu_per_block_seconds` mean or `/proc` | whole-process CPU / finalized block |\n'
    printf '| reverted sample | harness `receipt_sample.failed / queried` | bounded sample of last tx per sender |\n\n'

    printf '## Between-cell hygiene\n\n'
    printf 'Cells ran sequentially with a %ss settle window: the next cell started only\n' "$SETTLE"
    printf 'after the height advanced and `stell_mempoolSize` returned to 0, or the\n'
    printf 'window elapsed (then the report notes the inherited-load risk).\n\n'

    command_appendix

    printf '## Limits of this evidence\n\n'
    printf -- '- A 4-validator, empty-chain cell proves nothing about N=128 or about mainnet.\n'
    printf -- '- One host is both the load generator and (for local clusters) every validator; sender CPU and node CPU compete.\n'
    printf -- '- A cell below the offered rate is sender-bound **or** node-bound; this harness cannot distinguish them without a sender sweep.\n'
    printf -- '- Apply/block/CPU quantiles are bucket-interpolated from the node histograms; `+Inf` is reported as `>=`.\n'
    printf -- '- Confirmation is RPC-observed inclusion, not BFT finality time.\n'
    printf -- '- See `docs/PERF_MATRIX.md` for definitions, comparison rules and the full caveat list.\n'
  } > "$OUT/summary.md"

  if compgen -G "$OUT/cells/*/cell.json" > /dev/null; then
    jq -c . "$OUT"/cells/*/cell.json > "$OUT/matrix.jsonl" 2>/dev/null || true
  else
    : > "$OUT/matrix.jsonl"
  fi
}

# --- plan --------------------------------------------------------------------
print_plan() {
  local r
  IFS=',' read -r -a _rates <<< "$RATES"
  say "plan: cluster N=$VALIDATORS floor=${BLOCK_FLOOR_MS}ms rpc=$RPC metrics=${METRICS_URL:-none}"
  say "senders=$SENDERS duration=${DURATION}s settle=${SETTLE}s out=$OUT"
  for r in "${_rates[@]}"; do
    say "  would run: N=$VALIDATORS floor=$BLOCK_FLOOR_MS rate=$r"
  done
  say "matrix rendering will include N=$MATRIX_NS x floors=$MATRIX_FLOORS x rates=$RATES"
  say "unprovisioned clusters are rendered NOT MEASURED with a reason"
}

# ==============================================================================
# main
# ==============================================================================

if [[ -n "$RENDER_ONLY" ]]; then
  OUT="$RENDER_ONLY"
  [[ -d "$OUT" ]] || die "--render-only: no such directory $OUT"
  [[ -f "$OUT/meta.json" ]] || die "--render-only: $OUT/meta.json is missing"
  # Restore the scope recorded by the run so a re-render shows the same rows.
  _meta="$OUT/meta.json"
  MATRIX_NS="$(jq -r '.declared.matrix_ns // .declared.rates // "4,32,128"' "$_meta" 2>/dev/null || printf '4,32,128')"
  MATRIX_FLOORS="$(jq -r '.declared.matrix_floors // "400,250"' "$_meta" 2>/dev/null || printf '400,250')"
  RATES="$(jq -r '.declared.rates // "100,1000,5000"' "$_meta" 2>/dev/null || printf '100,1000,5000')"
  SETTLE="$(jq -r '.declared.settle_s // 30' "$_meta" 2>/dev/null || printf '30')"
  render_summary
  say "re-rendered $OUT/summary.md"
  exit 0
fi

(( ACK == 1 )) || die "pass --i-know-this-is-not-mainnet (load must never target mainnet)"
[[ -n "$RPC" || "$LOCAL_CLUSTER" == 1 ]] || die "--rpc URL is required (or --local-cluster)"
is_uint "$VALIDATORS" || die "--validators must be an integer"
is_uint "$BLOCK_FLOOR_MS" || die "--block-floor-ms must be an integer"
is_csv_uint "$RATES" || die "--rates must be comma-separated integers"
is_csv_uint "$MATRIX_NS" || die "--matrix-n must be comma-separated integers"
is_csv_uint "$MATRIX_FLOORS" || die "--matrix-floors must be comma-separated integers"
is_uint "$SENDERS" || die "--senders must be an integer"
is_uint "$DURATION" || die "--duration must be an integer"
is_uint "$DRAIN_TIMEOUT" || die "--drain-timeout must be an integer"
is_uint "$SETTLE" || die "--settle must be an integer"
is_uint "$PER_CELL_TIMEOUT" || die "--per-cell-timeout must be an integer"
[[ "$MAX_429_SHARE" =~ ^[0-9]*\.?[0-9]+$ ]] || die "--max-429-share must be a number"

VALIDATORS=$((10#$VALIDATORS))
BLOCK_FLOOR_MS=$((10#$BLOCK_FLOOR_MS))
SENDERS=$((10#$SENDERS))
DURATION=$((10#$DURATION))
DRAIN_TIMEOUT=$((10#$DRAIN_TIMEOUT))
SETTLE=$((10#$SETTLE))
PER_CELL_TIMEOUT=$((10#$PER_CELL_TIMEOUT))
RATES="$(normalize_csv "$RATES")"
MATRIX_NS="$(normalize_csv "$MATRIX_NS")"
MATRIX_FLOORS="$(normalize_csv "$MATRIX_FLOORS")"

(( VALIDATORS >= 1 )) || die "--validators must be >= 1"
(( BLOCK_FLOOR_MS >= 1 )) || die "--block-floor-ms must be >= 1"
(( SENDERS >= 1 && SENDERS <= 4096 )) || die "--senders must be 1..4096"
(( DURATION >= 5 )) || die "--duration must be >= 5 s"

if [[ -n "$CPU_PIDS" ]]; then
  is_csv_uint "$CPU_PIDS" || die "--cpu-pids must be comma-separated PIDs"
  CPU_PIDS="$(normalize_csv "$CPU_PIDS")"
fi

if (( LOCAL_CLUSTER == 1 )); then
  derive_local_cluster
fi

# The node's default per-IP RPC budget is 300/s. Warn before spending a cell on
# a rate the target cannot accept; the run still proceeds so the 429 evidence
# is recorded rather than assumed.
IFS=',' read -r -a _pre_rates <<< "$RATES"
for _pre_rate in "${_pre_rates[@]}"; do
  if (( _pre_rate > 250 )); then
    warn "offered ${_pre_rate} tx/s exceeds the default standalone RPC budget (300/s per IP); \
raise STELL_STANDALONE_RATE_LIMIT on the target or expect an INVALID (429) cell"
  fi
done

guard_url "--rpc" "$RPC"
if [[ -n "$METRICS_URL" ]]; then guard_url "--metrics-url" "$METRICS_URL"; fi

if [[ -z "$OUT" ]]; then
  OUT="$ROOT/run/perf-matrix/$(date -u '+%Y%m%dT%H%M%SZ')"
fi
mkdir -p "$OUT"

if (( PLAN == 1 )); then
  print_plan
  exit 0
fi

# One matrix invocation per results dir: a second concurrent writer would
# interleave cells and make the "one at a time" claim false.
if command -v flock >/dev/null 2>&1; then
  exec 9>"$OUT/.matrix.lock"
  flock -n 9 || die "another perf-matrix.sh holds $OUT/.matrix.lock"
fi

ensure_harness
verify_declared_floor

# Chain facts and the declared-N cross-check happen before any load.
CHAIN_ID="$(rpc_call stell_chainId 2>/dev/null | jq -r '.result // empty' 2>/dev/null || true)"
[[ -n "$CHAIN_ID" ]] || die "cannot read stell_chainId from $RPC (is the node up?)"
HEIGHT_NOW="$(rpc_height)"
(( HEIGHT_NOW > 0 )) || die "cannot read a non-zero stell_blockNumber from $RPC"
VALIDATORS_NOW="$(rpc_call stell_getValidators 2>/dev/null | jq -r '.result.validators | length' 2>/dev/null || true)"
if [[ -z "$VALIDATORS_NOW" || "$VALIDATORS_NOW" == "null" ]]; then
  die "stell_getValidators returned no validator list; cannot verify N=$VALIDATORS"
fi
if [[ "$VALIDATORS_NOW" != "$VALIDATORS" ]]; then
  if (( ALLOW_VALIDATOR_MISMATCH == 1 )); then
    warn "declared N=$VALIDATORS but the node reports $VALIDATORS_NOW validators (overridden)"
  else
    die "declared --validators $VALIDATORS but stell_getValidators reports $VALIDATORS_NOW"
  fi
fi
say "chain id $CHAIN_ID, height $HEIGHT_NOW, validators $VALIDATORS_NOW"

write_meta

# Funding gate: if the deterministic sender set is not funded, every cell is
# blocked (and the report says exactly that) instead of failing opaquely.
set +e
preflight_funding
pre_rc=$?
set -e
if (( pre_rc == 3 )); then
  record_blocked_all "deterministic sender set is underfunded; see senders.txt (harness never funds)"
  render_summary
  say "blocked: fund the roster in $OUT/senders.txt, then re-run (results keep this row set)"
  exit 3
elif (( pre_rc != 0 )); then
  die "preflight failed with exit $pre_rc; see $OUT/preflight.log"
fi

IFS=',' read -r -a _rates <<< "$RATES"
for _rate in "${_rates[@]}"; do
  run_cell "$VALIDATORS" "$BLOCK_FLOOR_MS" "$_rate"
  settle_between_cells
done

render_summary
say "summary: $OUT/summary.md"
say "raw cells: $OUT/cells/"
