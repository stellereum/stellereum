#!/usr/bin/env bash
# ==============================================================================
# fresh_genesis.sh — coordinated fresh-chain boot for Stellereum validators.
#
# The procedure this script automates (and prints before it does anything):
#
#   1. preflight: disk > 10 GiB free, node dir/env/unit present, binary digest
#   2. STOP every validator and verify it is stopped
#   3. atomically replace the binary at the unit's ExecStart path
#   4. wipe ONLY ./data (keys and configs are kept)
#   5. set STELL_NEW_CHAIN=1 in the unit's EnvironmentFile
#   6. START every validator
#   7. wait until every node's stell_blockNumber > 0
#   8. remove STELL_NEW_CHAIN (it is a founding flag, not a permanent setting)
#
# SAFETY
#   * DRY-RUN BY DEFAULT. Destructive actions require --yes.
#   * Every command is printed before it runs.
#   * If any step fails: print the last log lines, stop every node, remove the
#     temporary flag, and exit 1. Nodes are left STOPPED, never half-started.
#   * Secrets are not printed. Env files are edited in place, never dumped.
#
# NODE SPEC
#   --nodes "A=ssh:root@host:/root/nodeA,B=local:/home/imm/.../nodeB"
#
#   Optional attributes (append with ';'):
#     A=ssh:root@host:/root/nodeA;env=/root/env.A;svc=stell-nodeA;\
#       bin=/root/stellereum/target/release/stellereum;rpc=http://127.0.0.1:8545
#
#   scheme    ssh:TARGET:DIR   or   local:DIR
#   env=      EnvironmentFile (default: DIR/env.NAME, then DIR/../env.NAME)
#   svc=      systemd unit    (default: stell-nodeNAME)
#   scope=    system|user     (default: system)
#   bin=      binary path     (default: auto-detect under DIR / DIR/..)
#   rpc=      JSON-RPC URL    (default: loopback port 8545, except B=8546)
#   logcmd=   read-only log command for failure diagnostics (default: journalctl)
#   ssh_opts= extra ssh args, e.g. ssh_opts=-p 2222
#
# EXAMPLES
#   # 1. always rehearse first (no --yes = dry run)
#   scripts/fresh_genesis.sh \
#     --nodes "A=ssh:root@hostA:/root/nodeA;env=/root/env.A,\
#              B=local:/home/imm/stellereum-project/multinode/nodeB;scope=user" \
#     --binary target/release/stellereum
#
#   # 2. the same command with --yes actually does it
#   scripts/fresh_genesis.sh ... --binary ... --yes
# ==============================================================================
set -euo pipefail

PROG="$(basename "$0")"
DRY_RUN=1
ASSUME_YES=0
FORCE_DRY=0
NODES_SPEC=""
BINARY=""
KEEP_BINARY=0
WAIT_TIMEOUT=180
MIN_FREE_GB=10
LOG_LINES=50
POLL_SECS=3

declare -a NAMES=()
declare -A SCHEME=() SSH_TARGET=() SSH_OPTS=() DIR=()
declare -A SVC=() SCOPE=() ENVFILE=() BINPATH=() RPCURL=() LOGCMD=()
declare -A ORIG_FLAG=() FLAG_SET=()
FAILING=0

usage() {
    cat <<EOF
$PROG — stop, replace, wipe data/, found a fresh chain, verify height, remove flag

USAGE
  $PROG --nodes SPEC [--binary PATH] [options]

OPTIONS
  --nodes SPEC        required; see below
  --binary PATH       new binary to install on every node (required unless
                      --keep-binary, which skips replacement)
  --keep-binary       do not replace the binary
  --yes               allow the destructive run (without it: dry run)
  --dry-run           force a dry run even if --yes is present
  --timeout SEC       wait this long for height > 0 (default $WAIT_TIMEOUT)
  --min-free-gb N     require more than N GiB free per node (default $MIN_FREE_GB)
  --log-lines N       log lines to print on failure (default $LOG_LINES)
  --help              this text

NODE SPEC
  Comma-separated NAME=... entries. Two forms:
    A=ssh:user@host:/root/nodeA
    B=local:/home/imm/stellereum-project/multinode/nodeB
  Append ';key=value' for overrides:
    env=PATH      EnvironmentFile
    svc=NAME      systemd unit (default stell-nodeNAME)
    scope=system|user
    bin=PATH      binary path (default: auto-detect)
    rpc=URL       JSON-RPC URL (default loopback 8545, B=8546)
    logcmd=CMD    read-only log command for failure output
    ssh_opts=...  extra ssh options (e.g. ssh_opts=-p 2222)

WHAT IS DESTRUCTIVE
  Only ./data is removed. keys/, node.yaml and the EnvironmentFile are kept.
  STELL_NEW_CHAIN=1 is added for the first boot and removed on success.

EXIT CODES
  0 success (or a clean dry run)
  1 failure; all nodes left stopped and the temporary flag removed
  64 usage / preflight refusal (nothing was stopped or deleted)
EOF
}

die() {
    printf '%s: %s\n' "$PROG" "$*" >&2
    exit 64
}

need_value() {
    [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
}

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

q() { printf '%q' "$1"; }

redact_line() {
    sed -E \
        -e 's/((TOKEN|SECRET|PASS|PASSWORD|PASSPHRASE|PRIVATE)[A-Z0-9_]*)[=:][^[:space:]]+/\1=<redacted>/Ig' \
        -e 's#(https?://)[^/@[:space:]]+@#\1***@#g'
}

# ---- argument parsing -------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --nodes)        need_value "$@"; NODES_SPEC="$2"; shift 2 ;;
        --binary)       need_value "$@"; BINARY="$2"; shift 2 ;;
        --keep-binary)  KEEP_BINARY=1; shift ;;
        --yes)          ASSUME_YES=1; shift ;;
        --dry-run)      FORCE_DRY=1; shift ;;
        --timeout)      need_value "$@"; WAIT_TIMEOUT="$2"; shift 2 ;;
        --min-free-gb)  need_value "$@"; MIN_FREE_GB="$2"; shift 2 ;;
        --log-lines)    need_value "$@"; LOG_LINES="$2"; shift 2 ;;
        --help|-h)      usage; exit 0 ;;
        *)              die "unknown option: $1 (try --help)" ;;
    esac
done

if (( FORCE_DRY || !ASSUME_YES )); then
    DRY_RUN=1
else
    DRY_RUN=0
fi

[[ -n "$NODES_SPEC" ]] || die "--nodes is required (try --help)"
[[ "$WAIT_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || die "--timeout must be a positive integer"
[[ "$MIN_FREE_GB" =~ ^[0-9]+$ ]] || die "--min-free-gb must be an integer"
[[ "$LOG_LINES" =~ ^[1-9][0-9]*$ ]] || die "--log-lines must be a positive integer"

if (( ! DRY_RUN )); then
    if (( ! KEEP_BINARY )) && [[ -z "$BINARY" ]]; then
        die "refusing destructive run without --binary (or pass --keep-binary)"
    fi
fi

if (( DRY_RUN )); then
    printf '%s: DRY RUN — every action is printed, nothing is changed.\n' "$PROG"
    if (( ASSUME_YES )); then
        printf '%s: --yes was supplied but --dry-run wins.\n' "$PROG"
    fi
else
    printf '%s: APPLY MODE — this will stop validators and delete ./data.\n' "$PROG"
fi

# ---- node spec parsing ------------------------------------------------------
default_rpc_port() {
    case "$1" in
        A) printf '8545' ;;
        B) printf '8546' ;;
        *) printf '8545' ;;
    esac
}

parse_nodes() {
    local spec="$1" entry name rest scheme_and_rest first extras kv key val
    local -a entries pairs

    IFS=',' read -r -a entries <<< "$spec"
    for entry in "${entries[@]}"; do
        entry="$(trim "$entry")"
        [[ -n "$entry" ]] || continue
        [[ "$entry" == *=* ]] || die "bad --nodes entry (want NAME=...): $entry"
        name="$(trim "${entry%%=*}")"
        rest="$(trim "${entry#*=}")"
        [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || die "bad node name: $name"
        [[ -z "${DIR[$name]:-}" ]] || die "duplicate node name: $name"

        # Split the optional ';attr=value' tail first, so URLs keep their ':'.
        first="$rest"
        extras=""
        if [[ "$rest" == *';'* ]]; then
            first="${rest%%;*}"
            extras="${rest#*;}"
        fi

        case "$first" in
            ssh:*)
                SCHEME["$name"]="ssh"
                rest="${first#ssh:}"
                [[ "$rest" == *:* ]] || die "ssh node $name needs ssh:TARGET:DIR"
                SSH_TARGET["$name"]="$(trim "${rest%%:*}")"
                DIR["$name"]="$(trim "${rest#*:}")"
                ;;
            local:*)
                SCHEME["$name"]="local"
                DIR["$name"]="$(trim "${first#local:}")"
                ;;
            *)
                die "node $name: expected ssh:TARGET:DIR or local:DIR, got: $first"
                ;;
        esac
        [[ -n "${DIR[$name]}" ]] || die "node $name has an empty directory"

        # Defaults; attributes below override them.
        SVC["$name"]="stell-node${name}"
        SCOPE["$name"]="system"
        ENVFILE["$name"]=""                 # resolved in preflight
        BINPATH["$name"]=""                 # resolved in preflight
        RPCURL["$name"]="http://127.0.0.1:$(default_rpc_port "$name")"
        LOGCMD["$name"]=""
        SSH_OPTS["$name"]=""

        if [[ -n "$extras" ]]; then
            IFS=';' read -r -a pairs <<< "$extras"
            for kv in "${pairs[@]}"; do
                [[ -n "$kv" ]] || continue
                [[ "$kv" == *=* ]] || die "bad node attribute (want key=value): $kv"
                key="$(trim "${kv%%=*}")"
                val="$(trim "${kv#*=}")"
                case "$key" in
                    env)      ENVFILE["$name"]="$val" ;;
                    svc)      SVC["$name"]="$val" ;;
                    scope)    SCOPE["$name"]="$val" ;;
                    bin)      BINPATH["$name"]="$val" ;;
                    rpc)      RPCURL["$name"]="$val" ;;
                    logcmd)   LOGCMD["$name"]="$val" ;;
                    ssh_opts) SSH_OPTS["$name"]="$val" ;;
                    *)        die "node $name: unknown attribute: $key" ;;
                esac
            done
        fi

        [[ "${SCOPE[$name]}" == "system" || "${SCOPE[$name]}" == "user" ]] \
            || die "node $name: scope must be system or user"
        NAMES+=("$name")
    done

    (( ${#NAMES[@]} > 0 )) || die "--nodes parsed to zero nodes"
}

parse_nodes "$NODES_SPEC"

# ---- command helpers --------------------------------------------------------
systemctl_prefix() { # name -> "systemctl" or "systemctl --user"
    local n="$1"
    if [[ "${SCOPE[$n]}" == "user" ]]; then
        printf 'systemctl --user'
    else
        printf 'systemctl'
    fi
}

# Read-only command. Logs the command to stderr, returns stdout to the caller.
node_read() {
    local n="$1" cmd="$2"
    if [[ "${SCHEME[$n]}" == "ssh" ]]; then
        printf '[check] ssh %s %s %s\n' \
            "${SSH_OPTS[$n]:-}" "${SSH_TARGET[$n]}" "$(q "$cmd")" >&2
        # shellcheck disable=SC2086
        ssh ${SSH_OPTS[$n]:-} "${SSH_TARGET[$n]}" "$cmd"
    else
        printf '[check] %s\n' "$cmd" >&2
        bash -c "$cmd"
    fi
}

# Same as node_read but quiet (for polling loops).
node_capture() {
    local n="$1" cmd="$2"
    if [[ "${SCHEME[$n]}" == "ssh" ]]; then
        # shellcheck disable=SC2086
        ssh ${SSH_OPTS[$n]:-} "${SSH_TARGET[$n]}" "$cmd"
    else
        bash -c "$cmd"
    fi
}

# Mutating command. Prints every command first; does nothing in dry-run.
node_run() {
    local n="$1" cmd="$2"
    if [[ "${SCHEME[$n]}" == "ssh" ]]; then
        printf '+ ssh %s %s %s\n' \
            "${SSH_OPTS[$n]:-}" "${SSH_TARGET[$n]}" "$(q "$cmd")"
        if (( DRY_RUN )); then return 0; fi
        # shellcheck disable=SC2086
        ssh ${SSH_OPTS[$n]:-} "${SSH_TARGET[$n]}" "$cmd"
    else
        printf '+ %s\n' "$cmd"
        if (( DRY_RUN )); then return 0; fi
        bash -c "$cmd"
    fi
}

stop_cmd() { printf '%s stop %s' "$(systemctl_prefix "$1")" "$(q "${SVC[$1]}")"; }
start_cmd() { printf '%s start %s' "$(systemctl_prefix "$1")" "$(q "${SVC[$1]}")"; }
active_cmd() { printf '%s is-active --quiet %s' "$(systemctl_prefix "$1")" "$(q "${SVC[$1]}")"; }
active_state_cmd() { printf '%s show -p ActiveState --value %s' "$(systemctl_prefix "$1")" "$(q "${SVC[$1]}")"; }

set_flag_cmd() {
    local n="$1" env="${ENVFILE[$n]}" qenv
    qenv="$(q "$env")"
    # Replace an existing assignment, or append exactly one line. The extra
    # echo guarantees a separator even if the env file lacked a trailing LF.
    printf "if grep -q '^STELL_NEW_CHAIN=' %s; then sed -i 's/^STELL_NEW_CHAIN=.*/STELL_NEW_CHAIN=1/' %s; else echo >> %s; echo 'STELL_NEW_CHAIN=1' >> %s; fi" \
        "$qenv" "$qenv" "$qenv" "$qenv"
}

unset_flag_cmd() {
    local n="$1" env="${ENVFILE[$n]}" orig qenv expr esc
    qenv="$(q "$env")"
    orig="${ORIG_FLAG[$n]:-}"
    if [[ "$orig" == "__ABSENT__" || -z "$orig" ]]; then
        printf "sed -i '/^STELL_NEW_CHAIN=/d' %s" "$qenv"
    else
        # Escape only the REPLACEMENT text; the '|' delimiters stay intact.
        esc="${orig//\\/\\\\}"
        esc="${esc//&/\\&}"
        esc="${esc//|/\\|}"
        expr="s|^STELL_NEW_CHAIN=.*|${esc}|"
        printf 'sed -i %s %s' "$(q "$expr")" "$qenv"
    fi
}

# ---- failure path -----------------------------------------------------------
fail() {
    local msg="$*"
    trap - ERR
    set +e
    if (( FAILING )); then exit 1; fi
    FAILING=1
    printf '\n%s: FAILED: %s\n' "$PROG" "$msg" >&2

    if (( ! DRY_RUN )); then
        printf '%s: collecting last %s log lines (read-only)...\n' "$PROG" "$LOG_LINES" >&2
        for n in "${NAMES[@]}"; do
            printf '\n---- %s last %s lines (%s) ----\n' "$n" "$LOG_LINES" "${SVC[$n]}" >&2
            logcmd="${LOGCMD[$n]:-}"
            if [[ -n "$logcmd" ]]; then
                # A custom log command is complete as written (it may contain
                # its own ssh); run it from the operator box.
                timeout 30 bash -c "$logcmd" 2>&1 | tail -n "$LOG_LINES" | redact_line >&2
            else
                if [[ "${SCOPE[$n]}" == "user" ]]; then
                    logcmd="journalctl --user -u $(q "${SVC[$n]}") -n $LOG_LINES --no-pager"
                else
                    logcmd="journalctl -u $(q "${SVC[$n]}") -n $LOG_LINES --no-pager"
                fi
                # Default log command runs ON the node (over ssh when needed).
                # journalctl is bounded by -n and --no-pager; no wrapper needed.
                node_capture "$n" "$logcmd" 2>&1 | tail -n "$LOG_LINES" | redact_line >&2
            fi
        done

        # Remove the temporary founding flag while the nodes are stopped; a
        # later accidental start must not silently mint another chain.
        for n in "${NAMES[@]}"; do
            if [[ "${FLAG_SET[$n]:-0}" -eq 1 ]]; then
                printf '\n%s: removing temporary STELL_NEW_CHAIN from %s\n' "$PROG" "$n" >&2
                node_run "$n" "$(unset_flag_cmd "$n")" || true
                FLAG_SET["$n"]=0
            fi
        done

        # Leave every node stopped, even if only one failed.
        for n in "${NAMES[@]}"; do
            printf '\n%s: ensuring %s is stopped\n' "$PROG" "$n" >&2
            node_run "$n" "$(stop_cmd "$n")" || true
        done
        printf '\n%s: ALL NODES LEFT STOPPED. Fix the cause, then rerun this script.\n' "$PROG" >&2
    fi
    exit 1
}

trap 'rc=$?; if (( rc != 0 && FAILING == 0 )); then fail "unexpected command failure (exit $rc) at line $LINENO"; fi' ERR

# ---- preflight --------------------------------------------------------------
printf '\n%s: preflight (read-only)\n' "$PROG"

if (( ! KEEP_BINARY )) && [[ -n "$BINARY" ]]; then
    [[ -f "$BINARY" ]] || die "binary not found: $BINARY"
    if ! BIN_SHA="$(sha256sum "$BINARY" | awk '{print $1}')"; then
        die "could not hash binary: $BINARY"
    fi
    printf '[preflight] local binary: %s sha256=%s\n' "$BINARY" "$BIN_SHA"
else
    BIN_SHA=""
fi

for n in "${NAMES[@]}"; do
    printf '\n[preflight] %s (%s %s:%s)\n' \
        "$n" "${SCHEME[$n]}" "${SSH_TARGET[$n]:-local}" "${DIR[$n]}"

    # Directory must exist: we only replace ./data inside it.
    if ! node_read "$n" "test -d $(q "${DIR[$n]}")" >/dev/null 2>&1; then
        die "node $n: directory does not exist: ${DIR[$n]}"
    fi

    # Resolve EnvironmentFile if not given: DIR/env.NAME, then DIR/../env.NAME.
    if [[ -z "${ENVFILE[$n]}" ]]; then
        c1="${DIR[$n]}/env.${n}"
        c2="$(dirname "${DIR[$n]}")/env.${n}"
        if node_read "$n" "test -f $(q "$c1")" >/dev/null 2>&1; then
            ENVFILE["$n"]="$c1"
        elif node_read "$n" "test -f $(q "$c2")" >/dev/null 2>&1; then
            ENVFILE["$n"]="$c2"
        else
            ENVFILE["$n"]="$c1"
        fi
    fi
    if ! node_read "$n" "test -f $(q "${ENVFILE[$n]}")" >/dev/null 2>&1; then
        die "node $n: EnvironmentFile does not exist: ${ENVFILE[$n]}"
    fi

    # Resolve binary path if not given. Covers both live layouts:
    #   /root/nodeA  -> /root/stellereum/target/release/stellereum
    #   multinode/nodeB -> multinode/nodeB/stellereum
    if [[ -z "${BINPATH[$n]}" ]]; then
        cands=(
            "${DIR[$n]}/stellereum"
            "$(dirname "${DIR[$n]}")/stellereum/target/release/stellereum"
            "$(dirname "${DIR[$n]}")/stellereum/target/debug/stellereum"
            "${DIR[$n]}/target/release/stellereum"
        )
        found=""
        for c in "${cands[@]}"; do
            if node_read "$n" "test -x $(q "$c")" >/dev/null 2>&1; then
                found="$c"
                break
            fi
        done
        BINPATH["$n"]="${found:-${DIR[$n]}/stellereum}"
    fi
    if ! node_read "$n" "test -d $(q "$(dirname "${BINPATH[$n]}")")" >/dev/null 2>&1; then
        die "node $n: binary directory does not exist: $(dirname "${BINPATH[$n]}")"
    fi

    # Disk space: > MIN_FREE_GB GiB available on the filesystem holding DIR.
    free_kb="$(node_read "$n" "df -Pk $(q "${DIR[$n]}") | awk 'NR==2 {print \$4}'" 2>/dev/null | tail -n 1 | tr -d '[:space:]' || true)"
    [[ "$free_kb" =~ ^[0-9]+$ ]] || die "node $n: could not read free disk space"
    need_kb=$((MIN_FREE_GB * 1024 * 1024))
    free_gib="$(awk -v k="$free_kb" 'BEGIN { printf "%.1f", k / 1024 / 1024 }')"
    if (( free_kb <= need_kb )); then
        die "node $n: only ${free_gib} GiB free; fresh genesis needs more than ${MIN_FREE_GB} GiB"
    fi
    printf '  disk: %s GiB free (need > %s GiB)\n' "$free_gib" "$MIN_FREE_GB"

    # Unit must be known to systemd (read-only check).
    load="$(node_read "$n" "$(systemctl_prefix "$n") show -p LoadState --value $(q "${SVC[$n]}")" 2>/dev/null | tail -n 1 | tr -d '[:space:]' || true)"
    if [[ -n "$load" && "$load" != "loaded" ]]; then
        die "node $n: unit ${SVC[$n]} LoadState=$load (wrong svc= or scope=?)"
    fi

    # Remember the current STELL_NEW_CHAIN line so it can be restored exactly.
    orig="$(node_read "$n" "grep -m1 '^STELL_NEW_CHAIN=' $(q "${ENVFILE[$n]}") || true" 2>/dev/null | tail -n 1 || true)"
    if [[ -n "$orig" ]]; then
        ORIG_FLAG["$n"]="$orig"
        printf '  flag: existing STELL_NEW_CHAIN line present (will be restored)\n'
    else
        ORIG_FLAG["$n"]="__ABSENT__"
        printf '  flag: STELL_NEW_CHAIN absent (added for first boot, removed after)\n'
    fi
    FLAG_SET["$n"]=0

    printf '  env=%s\n  svc=%s (%s)\n  bin=%s\n  rpc=%s\n' \
        "${ENVFILE[$n]}" "${SVC[$n]}" "${SCOPE[$n]}" "${BINPATH[$n]}" "${RPCURL[$n]}"
done

printf '\n[plan] actions per node: stop -> verify stopped -> replace binary -> wipe data/ -> set STELL_NEW_CHAIN -> start -> wait height>0 -> remove flag\n'
if (( KEEP_BINARY )); then
    printf '[plan] binary replacement: SKIPPED (--keep-binary)\n'
elif [[ -n "$BINARY" ]]; then
    printf '[plan] binary replacement: %s -> all nodes (sha256 %s)\n' "$BINARY" "$BIN_SHA"
else
    printf '[plan] binary replacement: SKIPPED (dry run without --binary)\n'
fi
printf '[plan] nodes: %s\n' "${NAMES[*]}"

# ---- 1. stop ----------------------------------------------------------------
printf '\n%s: stopping validators\n' "$PROG"
for n in "${NAMES[@]}"; do
    if node_read "$n" "$(active_cmd "$n")" >/dev/null 2>&1; then
        node_run "$n" "$(stop_cmd "$n")" || fail "could not stop $n"
    else
        printf '[stop] %s already stopped (%s)\n' "$n" "${SVC[$n]}"
    fi
done

# Verify; in dry-run the services were intentionally not touched.
if (( ! DRY_RUN )); then
    for n in "${NAMES[@]}"; do
        state="$(node_capture "$n" "$(active_state_cmd "$n")" 2>/dev/null | tail -n 1 | tr -d '[:space:]')"
        case "$state" in
            inactive|failed)
                printf '[stop] %s verified stopped (ActiveState=%s)\n' "$n" "$state"
                ;;
            *)
                fail "node $n is not safely stopped (ActiveState=${state:-unknown}); refusing to touch data"
                ;;
        esac
    done
else
    printf '[dry-run] stop verification skipped (services are not touched)\n'
fi

# ---- 2. replace binary ------------------------------------------------------
if (( KEEP_BINARY )); then
    printf '\n%s: binary replacement skipped (--keep-binary)\n' "$PROG"
elif [[ -z "$BINARY" ]]; then
    printf '\n%s: binary replacement skipped (dry run without --binary)\n' "$PROG"
else
    printf '\n%s: replacing binary\n' "$PROG"
    for n in "${NAMES[@]}"; do
        tmp="${BINPATH[$n]}.fresh-genesis.tmp"
        if [[ "${SCHEME[$n]}" == "ssh" ]]; then
            remote="cat > $(q "$tmp") && chmod 0755 $(q "$tmp") && mv -f $(q "$tmp") $(q "${BINPATH[$n]}")"
            printf '+ cat %s | ssh %s %s %s\n' \
                "$BINARY" "${SSH_OPTS[$n]:-}" "${SSH_TARGET[$n]}" "$(q "$remote")"
            if (( ! DRY_RUN )); then
                # shellcheck disable=SC2086
                cat "$BINARY" | ssh ${SSH_OPTS[$n]:-} "${SSH_TARGET[$n]}" "$remote" \
                    || fail "binary upload failed for $n"
            fi
        else
            cmd="install -m 0755 $(q "$BINARY") $(q "$tmp") && mv -f $(q "$tmp") $(q "${BINPATH[$n]}")"
            node_run "$n" "$cmd" || fail "binary install failed for $n"
        fi

        if (( ! DRY_RUN )); then
            got="$(node_capture "$n" "sha256sum $(q "${BINPATH[$n]}") | awk '{print \$1}'" | tail -n 1 | tr -d '[:space:]')"
            [[ "$got" == "$BIN_SHA" ]] \
                || fail "binary digest mismatch on $n (got ${got:-none}, want $BIN_SHA)"
            printf '[binary] %s sha256 verified\n' "$n"
        fi
    done
fi

# ---- 3. wipe data -----------------------------------------------------------
printf '\n%s: wiping data/ (keys and configs kept)\n' "$PROG"
for n in "${NAMES[@]}"; do
    node_run "$n" "rm -rf $(q "${DIR[$n]}/data") && mkdir -p $(q "${DIR[$n]}/data")" \
        || fail "could not wipe data for $n"
done

# ---- 4. set temporary founding flag ----------------------------------------
printf '\n%s: setting STELL_NEW_CHAIN=1 for the first boot\n' "$PROG"
for n in "${NAMES[@]}"; do
    node_run "$n" "$(set_flag_cmd "$n")" || fail "could not set STELL_NEW_CHAIN on $n"
    FLAG_SET["$n"]=1
done

# ---- 5. start ---------------------------------------------------------------
printf '\n%s: starting validators\n' "$PROG"
for n in "${NAMES[@]}"; do
    node_run "$n" "$(start_cmd "$n")" || fail "could not start $n"
done

# ---- 6. wait for height > 0 -------------------------------------------------
node_height() { # name -> decimal height or empty
    local n="$1" out hex
    out="$(node_capture "$n" "curl -sS --max-time 5 -H 'content-type: application/json' --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_blockNumber\",\"params\":[]}' $(q "${RPCURL[$n]}")" 2>/dev/null || true)"
    hex="$(printf '%s' "$out" | sed -n 's/.*"result":"\(0x[0-9a-fA-F]*\)".*/\1/p' | head -n 1)"
    [[ -n "$hex" ]] || return 1
    printf '%d' "$((16#${hex#0x}))"
}

if (( DRY_RUN )); then
    printf '\n[dry-run] would wait up to %ss for stell_blockNumber > 0 on: %s\n' \
        "$WAIT_TIMEOUT" "${NAMES[*]}"
    printf '[dry-run] would then remove STELL_NEW_CHAIN and print the height table\n'
else
    printf '\n%s: waiting up to %ss for height > 0 on every node\n' "$PROG" "$WAIT_TIMEOUT"
    deadline=$((SECONDS + WAIT_TIMEOUT))
    ready=0
    while (( SECONDS < deadline )); do
        ready=1
        status=""
        for n in "${NAMES[@]}"; do
            if h="$(node_height "$n")" && (( h > 0 )); then
                status+=" $n=$h"
            else
                status+=" $n=0"
                ready=0
            fi
        done
        printf '[wait]%s\n' "$status"
        if (( ready )); then break; fi
        sleep "$POLL_SECS"
    done
    (( ready )) || fail "height did not advance above 0 within ${WAIT_TIMEOUT}s"
fi

# ---- 7. remove temporary flag ----------------------------------------------
printf '\n%s: removing STELL_NEW_CHAIN (founding is complete)\n' "$PROG"
for n in "${NAMES[@]}"; do
    if [[ "${FLAG_SET[$n]:-0}" -eq 1 ]]; then
        node_run "$n" "$(unset_flag_cmd "$n")" || fail "could not remove STELL_NEW_CHAIN on $n"
        FLAG_SET["$n"]=0
    fi
done

# ---- success ----------------------------------------------------------------
printf '\n%s: fresh genesis complete\n' "$PROG"
if (( ! DRY_RUN )); then
    printf '  heights:\n'
    for n in "${NAMES[@]}"; do
        h="$(node_height "$n" 2>/dev/null || printf '?')"
        printf '    %-4s %s\n' "$n" "$h"
    done
    printf '\n  verify liveness/divergence (read-only):\n'
    printf '    scripts/cluster_liveness.sh --rpcs "A=%s,B=%s" ...\n' \
        "${RPCURL[A]:-http://127.0.0.1:8545}" "${RPCURL[B]:-http://127.0.0.1:8546}"
    printf '  verify /health verdict and the same block hash at a common height:\n'
    printf '    see docs/FRESH_GENESIS_RUNBOOK.md\n'
else
    printf '  [dry-run] no changes were made. Rerun with --yes to apply.\n'
fi
