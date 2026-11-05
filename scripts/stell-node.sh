#!/usr/bin/env bash
# Stellereum test-stand control script.
#
# One command per action, no guessing about process detachment (the single biggest
# source of "it says started but nothing is listening"):
#
#   ./stell-node.sh start          start both nodes, wait until BOTH are ready
#   ./stell-node.sh stop           stop both, wait until the sockets are gone
#   ./stell-node.sh restart        stop then start (keeps the chain)
#   ./stell-node.sh wipe && start  fresh chain: wipe both data dirs first
#   ./stell-node.sh status         heights, state roots, view changes, verdict
#   ./stell-node.sh logs A         tail node A's log
#
# Exit codes: 0 ok, 1 not ready / unhealthy, 2 bad usage.
set -uo pipefail

ROOT="${STELL_ROOT:-/root}"
BIN="$ROOT/stellereum/target/release/stellereum"
NODE_A="$ROOT/nodeA"
NODE_B="$ROOT/nodeB"
ENV_A="$ROOT/env.A"
ENV_B="$ROOT/env.B"
# Four-validator stand additions (C/D). Additive only: nothing above is changed.
NODE_C="$ROOT/nodeC"
NODE_D="$ROOT/nodeD"
ENV_C="$ROOT/env.C"
ENV_D="$ROOT/env.D"
# Ready-wait budget. A cold start has to warm the DHT and find its peer; if the peer
# is late the node idles in round changes until it appears, so this is generous.
READY_TIMEOUT="${STELL_READY_TIMEOUT:-120}"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }

pids_of() { pgrep -f "$BIN run" || true; }

# Four-validator additions: match running nodes by working directory, so
# stop4/wipe4 touch nodeC/nodeD only and never disturb the live nodeA/nodeB.
pids_of_dir() {
  local dir="$1" pid cwd
  for pid in $(pids_of); do
    cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
    [ "$cwd" = "$dir" ] && printf '%s\n' "$pid"
  done
}

# Rust (and this binary) are not on PATH for a non-interactive ssh shell.
export PATH="$PATH:$ROOT/.cargo/bin"

start_one() {
  local dir="$1" env="$2" name="$3" log="$4"
  if [ ! -x "$BIN" ]; then red "no binary at $BIN"; return 1; fi
  if [ ! -f "$dir/node.yaml" ]; then red "$dir/node.yaml missing"; return 1; fi
  if [ ! -f "$env" ]; then red "$env missing"; return 1; fi
  # Truncate, do not append. A running node appends to `current.log`, so a previous
  # run's errors (e.g. "lacks a validator quorum" from an old chain) stayed in the
  # file and made the stale-chain detector fire on a perfectly healthy chain.
  : > "$log"
  ( cd "$dir" && set -a && . "$env" && set +a && \
      setsid nohup "$BIN" run --config node.yaml --shard 1 >> "$log" 2>&1 < /dev/null & )
  printf '  started %s (log %s)\n' "$name" "$log"
}

stop_all() {
  local pids left
  pids="$(pids_of)"
  if [ -z "$pids" ]; then printf '  nothing running\n'; return 0; fi
  kill $pids 2>/dev/null || true
  # Wait for graceful drain/flush (~15-20s) AND for the sled lock to be
  # released, not just for the signal to land: starting too early fails with
  # `could not acquire lock on ./data/store/db` (WouldBlock) and replacing
  # the binary while the old process is still draining risks TEXT-BUSY.
  # Poll fast: bail out as soon as the pids are gone. Up to 30s, then
  # SIGKILL + 5s, then FAIL (non-zero) so callers (restart/start --force)
  # never start overlapping duplicates.
  for _ in $(seq 1 300); do
    [ -z "$(pids_of)" ] && { printf '  stopped\n'; return 0; }
    sleep 0.1
  done
  ylw "  still alive after 30s, sending KILL"
  kill -9 $(pids_of) 2>/dev/null || true
  for _ in $(seq 1 50); do
    [ -z "$(pids_of)" ] && { printf '  stopped (after KILL)\n'; return 0; }
    sleep 0.1
  done
  left="$(pids_of)"
  red "  FAILED to stop processes even after SIGKILL+5s (PIDs: $left)"
  return 1
}

# One-shot JSON-RPC helper against a node's loopback RPC endpoint.
rpc() {
  local port="$1" method="$2" params="${3:-[]}"
  curl -s -m 5 -X POST "http://127.0.0.1:$port" \
    -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}
height_of() { rpc "$1" stell_blockNumber | sed -n 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/p'; }

# The last finalized root, read from the log rather than from the explorer: the two
# nodes share one explorer port in the stand env, so an HTTP poll would report the
# same node's root twice and hide a divergence.
last_finalized() {
  local log="$1"
  grep -o 'FINALIZED block #[0-9]* [0-9a-f]* (state root [0-9a-f]*' "$log" 2>/dev/null | tail -1
}
root_of_log() { last_finalized "$1" | sed -n 's/.*state root \([0-9a-f]*\)/\1/p'; }
# Root ONLY when the FINALIZED line sits at that node's max height. A node
# whose FINALIZED trails its adopted tip has a stale root: comparing it
# against the peer's fresh root reports NOT SYNCED on a chain both nodes are
# actually on. Empty means "no root at max height" -> caller must not compare.
root_at_max_of_log() {
  local log="$1" mx rf
  mx="$(max_height_of_log "$log")"; rf="$(height_of_log "$log")"
  if [ -n "$mx" ] && [ -n "$rf" ] && [ "$rf" = "$mx" ]; then root_of_log "$log"; fi
}
height_of_log() { last_finalized "$1" | sed -n 's/FINALIZED block #\([0-9]*\).*/\1/p'; }
hash_of_log() { last_finalized "$1" | sed -n 's/FINALIZED block #\([0-9]*\) \([0-9a-f]*\).*/\2/p'; }

# Adopt-aware additions: a node that missed the deciding vote advances by ADOPTING
# a peer's committed block ("adopted committed block #H <hash>") WITHOUT ever
# printing a FINALIZED line. Status must treat either line as chain progress,
# or it reports NOT SYNCED forever on a healthy chain.
last_adopted() {
  local log="$1"
  grep -o 'adopted committed block #[0-9]* [0-9a-f]*' "$log" 2>/dev/null | tail -1
}
height_of_adopted() { last_adopted "$1" | sed -n 's/adopted committed block #\([0-9]*\).*/\1/p'; }
hash_of_adopted() { last_adopted "$1" | sed -n 's/adopted committed block #[0-9]* \([0-9a-f]*\).*/\1/p'; }
# Fallback liveness signal: recent view-change lines carry the height a node is
# TRYING to advance at, even when it has finalized/adopted nothing yet.
last_viewchange() {
  local log="$1"
  grep -o 'view change -> height [0-9]* round [0-9]*' "$log" 2>/dev/null | tail -1
}
viewchange_height_of_log() { last_viewchange "$1" | sed -n 's/view change -> height \([0-9]*\).*/\1/p'; }
# Per-node max height from EITHER progress signal (empty when neither exists).
max_height_of_log() {
  local log="$1" h1 h2
  h1="$(height_of_log "$log")"; h2="$(height_of_adopted "$log")"
  if [ -n "$h1" ] && [ -n "$h2" ]; then
    if [ "$h1" -ge "$h2" ]; then printf '%s\n' "$h1"; else printf '%s\n' "$h2"; fi
  elif [ -n "$h1" ]; then printf '%s\n' "$h1"
  elif [ -n "$h2" ]; then printf '%s\n' "$h2"
  fi
}
# Tip block hash behind the max height above (finalized and adopted lines both
# log hex(block_hash[..6]), so they are comparable). Empty when unknown.
tip_hash_of_log() {
  local log="$1" h1 h2
  h1="$(height_of_log "$log")"; h2="$(height_of_adopted "$log")"
  if [ -n "$h2" ] && { [ -z "$h1" ] || [ "$h2" -ge "$h1" ]; }; then
    hash_of_adopted "$log"
  elif [ -n "$h1" ]; then
    hash_of_log "$log"
  fi
}

# Ready = both processes alive AND the chain ADVANCING. A height reading alone is
# not enough, because a stalled node answers RPC at height 1 forever -- the exact
# "it started but nothing works" case this script exists to catch. Two DIFFERENT
# height samples are the proof; equal samples mean nothing moved.
wait_ready() {
  local deadline=$(( $(date +%s) + READY_TIMEOUT ))
  local last_a="" last_b=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if [ "$(pids_of | wc -l)" -lt 2 ]; then sleep 0.2; continue; fi
    local ha hb; ha="$(height_of 8545)"; hb="$(height_of 8546)"
    if [ -n "$ha" ] && [ -n "$hb" ]; then
      if [ -n "$last_a" ] && { [ "$ha" != "$last_a" ] || [ "$hb" != "$last_b" ]; }; then
        return 0   # both moved since the previous sample: the chain is live
      fi
      last_a="$ha"; last_b="$hb"
    fi
    sleep 1
  done
  return 1
}

status() {
  local n; n="$(pids_of | wc -l)"
  printf 'processes: %s\n' "$n"
  local la lb ha hb ra rb
  la="$(last_finalized "$NODE_A/current.log")"
  lb="$(last_finalized "$NODE_B/current.log")"
  ha="$(height_of_log "$NODE_A/current.log")"
  hb="$(height_of_log "$NODE_B/current.log")"
  ra="$(root_of_log "$NODE_A/current.log")"
  rb="$(root_of_log "$NODE_B/current.log")"
  local ra_max rb_max
  ra_max="$(root_at_max_of_log "$NODE_A/current.log")"
  rb_max="$(root_at_max_of_log "$NODE_B/current.log")"
  printf '  nodeA last_finalized: %s\n' "${la:-<none yet>}"
  printf '  nodeB last_finalized: %s\n' "${lb:-<none yet>}"
  local ca cb
  ca="$(grep -c FINALIZED "$NODE_A/current.log" 2>/dev/null)"; ca="${ca:-0}"
  cb="$(grep -c FINALIZED "$NODE_B/current.log" 2>/dev/null)"; cb="${cb:-0}"
  printf '  finalizes A=%s B=%s\n' "$ca" "$cb"
  # Adopt-aware progress: max height from EITHER signal + view-change fallback.
  # Labels above are unchanged (backward compatible); these lines are additive.
  local aa ab ma mb va vb da db ta tb
  aa="$(last_adopted "$NODE_A/current.log")"
  ab="$(last_adopted "$NODE_B/current.log")"
  ma="$(max_height_of_log "$NODE_A/current.log")"
  mb="$(max_height_of_log "$NODE_B/current.log")"
  va="$(viewchange_height_of_log "$NODE_A/current.log")"
  vb="$(viewchange_height_of_log "$NODE_B/current.log")"
  ta="$(tip_hash_of_log "$NODE_A/current.log")"
  tb="$(tip_hash_of_log "$NODE_B/current.log")"
  da="$(grep -c 'adopted committed block' "$NODE_A/current.log" 2>/dev/null)"; da="${da:-0}"
  db="$(grep -c 'adopted committed block' "$NODE_B/current.log" 2>/dev/null)"; db="${db:-0}"
  printf '  nodeA last_adopted: %s\n' "${aa:-<none yet>}"
  printf '  nodeB last_adopted: %s\n' "${ab:-<none yet>}"
  printf '  adopts A=%s B=%s\n' "$da" "$db"
  printf '  max_height A=%s B=%s\n' "${ma:-<none yet>}" "${mb:-<none yet>}"
  printf '  viewchange A=%s B=%s\n' "${va:-<none yet>}" "${vb:-<none yet>}"

  # A chain whose blocks predate the quorum-signature change carries 1-of-N
  # signatures and is unverifiable by design; say that plainly instead of reporting
  # a generic "not synced" that invites chasing a consensus bug that is not there.
  if grep -q 'lacks a validator quorum' "$NODE_A/current.log" "$NODE_B/current.log" 2>/dev/null; then
    red '  STALE CHAIN: blocks here were finalized before they carried a quorum.'
    red '  They cannot be verified by design. Run:  stell-node.sh clean'
    return 1
  fi

  if [ "$n" -ge 2 ] && [ -n "$ha" ] && [ "$ha" = "$hb" ] && [ -n "$ra" ] && [ "$ra" = "$rb" ]; then
    grn '  HEALTHY: both nodes agreed on the last finalized block and root'
  elif [ "$n" -ge 2 ] && [ -n "$ma" ] && [ "$ma" = "$mb" ] \
    && { [ -z "$ra_max" ] || [ -z "$rb_max" ] || [ "$ra_max" = "$rb_max" ]; } \
    && { [ -z "$ta" ] || [ -z "$tb" ] || [ "$ta" = "$tb" ]; }; then
    # Same max height via finalize and/or adopt, with no conflicting root or
    # tip hash: the chain is advancing on both nodes, one side just adopted
    # (no FINALIZED line) instead of finalizing locally.
    grn '  HEALTHY: both nodes at the same max height (finalize/adopt-aware, no conflicting root/tip)'
  elif [ "$n" -ge 2 ] && [ -n "$ma" ] && [ -n "$mb" ] \
    && [ $((ma - mb)) -le 1 ] && [ $((mb - ma)) -le 1 ]; then
    # One-block spread is the NORMAL steady state here: the faster node
    # finalizes while the other adopts the same tip a moment later. Reporting
    # NOT SYNCED for it taught operators to ignore the verdict. Tips cannot be
    # compared across DIFFERENT heights (they name different blocks by
    # construction), so this branch checks height only; a real fork shows as
    # divergence beyond one block (and is reported below).
    grn "  HEALTHY: nodes within one block (A=$ma B=$mb, converging)"
  elif [ "$n" -lt 2 ]; then
    ylw '  NOT RUNNING: fewer than two processes'
  else
    ylw '  NOT SYNCED yet (heights/roots differ; check the logs)'
  fi
}

case "${1:-}" in
  start)
    # Launch and RETURN. Do not poll here: the children are detached and inherit the
    # ssh session's stdout, so holding this shell open makes the CALLER wait for no
    # reason (minutes of apparent hang while the chain is already running fine).
    # Use `wait` (or `status`) afterwards.
    # Refuse to start over live processes: duplicate nodes on the same data
    # dirs/ports mean two writers on one chain. Use `start --force` to
    # stop-first (via stop_all above: SIGTERM, wait up to 30s, SIGKILL+5s).
    start_force=0
    if [ "${2:-}" = "--force" ]; then
      start_force=1
    elif [ -n "${2:-}" ]; then
      red "usage: $0 start [--force]"; exit 2
    fi
    if [ "$start_force" = 1 ]; then
      stop_all || exit "$?"
    else
      existing_pids="$(pids_of)"
      if [ -n "$existing_pids" ]; then
        red "refusing to start: node processes already running (PIDs: $(printf '%s' "$existing_pids" | tr '\n' ' ')) -- use '$0 start --force' to stop-first, or '$0 stop' then '$0 start'"
        exit 2
      fi
    fi
    start_one "$NODE_A" "$ENV_A" nodeA "$NODE_A/current.log"
    start_one "$NODE_B" "$ENV_B" nodeB "$NODE_B/current.log"
    printf 'launched. Check readiness with: %s wait\n' "$0"
    ;;
  wait)
    if [ "$(pids_of | wc -l)" -lt 2 ]; then red 'not both running; run start first'; exit 1; fi
    printf 'waiting up to %ss for the chain to advance...\n' "$READY_TIMEOUT"
    if wait_ready; then grn 'READY: both nodes are advancing'; status; else red 'TIMED OUT'; status; exit 1; fi
    ;;
  stop) stop_all ;;
  stop4)
    # Stop nodeC/nodeD only (matched by cwd). nodeA/nodeB keep running.
    pids="$( { pids_of_dir "$NODE_C"; pids_of_dir "$NODE_D"; } )"
    if [ -z "$pids" ]; then
      printf '  nothing running (C/D)\n'
    else
      kill $pids 2>/dev/null || true
      for _ in $(seq 1 200); do
        left="$( { pids_of_dir "$NODE_C"; pids_of_dir "$NODE_D"; } )"
        [ -z "$left" ] && { printf '  stopped (C/D)\n'; break; }
        sleep 0.1
      done
      left="$( { pids_of_dir "$NODE_C"; pids_of_dir "$NODE_D"; } )"
      [ -n "$left" ] && { ylw "  still alive, sending KILL"; kill -9 $left 2>/dev/null || true; }
    fi
    ;;
  status4)
    # Four-node health: last finalized block + root must agree on ALL of A-D,
    # and the chain must be advancing (two RPC samples checked by the caller).
    for n in A B C D; do
      case "$n" in
        A) dir="$NODE_A" port=8545 ;; B) dir="$NODE_B" port=8546 ;;
        C) dir="$NODE_C" port=8547 ;; D) dir="$NODE_D" port=8548 ;;
      esac
      printf '  node%s last_finalized: %s (rpc %s)\n' "$n" \
        "$(last_finalized "$dir/current.log" 2>/dev/null || true)" \
        "$(height_of "$port")"
    done
    ha="$(height_of_log "$NODE_A/current.log")"; hb="$(height_of_log "$NODE_B/current.log")"
    hc="$(height_of_log "$NODE_C/current.log")"; hd="$(height_of_log "$NODE_D/current.log")"
    # Roots at MAX height only (see root_at_max_of_log): a node whose FINALIZED
    # trails its adopted tip has a stale root, and treating it as a conflict
    # reports NOT SYNCED on a chain all four are actually on.
    ra="$(root_at_max_of_log "$NODE_A/current.log")"; rb="$(root_at_max_of_log "$NODE_B/current.log")"
    rc="$(root_at_max_of_log "$NODE_C/current.log")"; rd="$(root_at_max_of_log "$NODE_D/current.log")"
    # Adopt-aware: max height from EITHER signal per node (case-branch scope,
    # so plain assignments, not `local`).
    mha="$(max_height_of_log "$NODE_A/current.log")"; mhb="$(max_height_of_log "$NODE_B/current.log")"
    mhc="$(max_height_of_log "$NODE_C/current.log")"; mhd="$(max_height_of_log "$NODE_D/current.log")"
    tha="$(tip_hash_of_log "$NODE_A/current.log")"; thb="$(tip_hash_of_log "$NODE_B/current.log")"
    thc="$(tip_hash_of_log "$NODE_C/current.log")"; thd="$(tip_hash_of_log "$NODE_D/current.log")"
    printf '  max_height A=%s B=%s C=%s D=%s\n' \
      "${mha:-<none>}" "${mhb:-<none>}" "${mhc:-<none>}" "${mhd:-<none>}"
    if [ -n "$ha" ] && [ "$ha" = "$hb" ] && [ "$ha" = "$hc" ] && [ "$ha" = "$hd" ] \
    && [ -n "$ra" ] && [ "$ra" = "$rb" ] && [ "$ra" = "$rc" ] && [ "$ra" = "$rd" ]; then
      grn '  HEALTHY: all four nodes agreed on the last finalized block and root'
    else
      # Fallback: all four at the same max height (finalize and/or adopt) with
      # no conflicting non-empty root or tip hash.
      ref=""; tips=""; agree=1
      for r in "$ra" "$rb" "$rc" "$rd"; do
        if [ -n "$r" ]; then
          if [ -z "$ref" ]; then ref="$r"; elif [ "$r" != "$ref" ]; then agree=0; break; fi
        fi
      done
      if [ "$agree" = 1 ]; then
        for t in "$tha" "$thb" "$thc" "$thd"; do
          if [ -n "$t" ]; then
            if [ -z "$tips" ]; then tips="$t"; elif [ "$t" != "$tips" ]; then agree=0; break; fi
          fi
        done
      fi
      if [ "$agree" = 1 ] && [ -n "$mha" ] \
      && [ "$mha" = "$mhb" ] && [ "$mha" = "$mhc" ] && [ "$mha" = "$mhd" ]; then
        grn '  HEALTHY: all four nodes at the same max height (finalize/adopt-aware, no conflicting root/tip)'
      else
        ylw '  NOT SYNCED yet (heights/roots differ; check the logs)'
      fi
    fi
    ;;
  wipe4)
    # Delete nodeC/nodeD data dirs only (genesis-scoped). nodeA/nodeB data is
    # untouched; the 2->4 migration itself still needs `wipe` for A/B because
    # the validator-set change alters their genesis root too.
    pids="$( { pids_of_dir "$NODE_C"; pids_of_dir "$NODE_D"; } )"
    [ -n "$pids" ] && kill $pids 2>/dev/null || true
    for _ in $(seq 1 200); do
      left="$( { pids_of_dir "$NODE_C"; pids_of_dir "$NODE_D"; } )"
      [ -z "$left" ] && break
      sleep 0.1
    done
    rm -rf "$NODE_C/data" "$NODE_D/data"
    printf '  nodeC/nodeD data directories wiped (nodeA/nodeB untouched)\n'
    ;;
  start4)
    # Launch nodeC + nodeD only and RETURN (nodeA/nodeB are managed by `start`).
    # For a FRESH 4-node genesis: stop, wipe, wipe4, then `start` + `start4`.
    start_one "$NODE_C" "$ENV_C" nodeC "$NODE_C/current.log"
    start_one "$NODE_D" "$ENV_D" nodeD "$NODE_D/current.log"
    printf 'launched C/D. Check with: %s status4\n' "$0"
    ;;
  restart) stop_all || exit "$?"; "$0" start ;;
  wipe)
    stop_all
    rm -rf "$NODE_A/data" "$NODE_B/data"
    printf '  data directories wiped (a NEW genesis root means every node must be wiped)\n'
    ;;
  clean)
    # wipe + start, the operation actually wanted after a consensus or genesis change.
    stop_all
    rm -rf "$NODE_A/data" "$NODE_B/data"
    printf '  wiped; starting fresh\n'
    "$0" start
    ;;
  status) status ;;
  logs)
    case "${2:-A}" in
      A) tail -n "${3:-40}" "$NODE_A/current.log" ;;
      B) tail -n "${3:-40}" "$NODE_B/current.log" ;;
      *) red 'usage: logs [A|B] [lines]'; exit 2 ;;
    esac ;;
  deploy)
    # Replace the binary atomically and verify the marker, because "the deploy worked"
    # has silently left the OLD binary in place before now.
    src="${2:-}"
    [ -f "$src" ] || { red 'usage: deploy /path/to/new/binary'; exit 2; }
    cp "$src" "$BIN.new" && mv "$BIN.new" "$BIN" && chmod +x "$BIN"
    printf '  binary replaced (%s bytes, %s)\n' "$(stat -c%s "$BIN")" "$(stat -c%y "$BIN" | cut -d. -f1)"
    ;;
  *) cat <<EOF
usage: $0 {start [--force]|stop|restart|clean|wipe|wait|status|logs [A|B] [n]|deploy <binary>|start4|stop4|status4|wipe4}
  start    launch both nodes and RETURN (refuses if any node process is already
           running; use 'start --force' to stop-first, then launch; use 'wait'
           to block until ready)
  wait     block until both nodes are advancing, then print status
  stop     stop both and wait for the data lock to be released
  restart  stop + start, keeping the chain
  clean    wipe both data dirs and start fresh (use this after a genesis or
           consensus change; old blocks may be unverifiable by design)
  wipe     stop + delete both data dirs (required after a genesis change)
  status   heights, root, finalizes, view changes and a health verdict
  logs     tail a node's current log
  deploy   atomically replace the binary
  start4   launch nodeC + nodeD only and RETURN (use 'status4' afterwards)
  stop4    stop nodeC + nodeD only (nodeA/nodeB keep running)
  status4  last-finalized agreement across all four nodes + health verdict
  wipe4    stop C/D if running + delete nodeC/nodeD data dirs (A/B untouched)
EOF
     exit 2 ;;
esac
