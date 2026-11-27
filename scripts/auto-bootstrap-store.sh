#!/usr/bin/env bash
# ==============================================================================
# auto-bootstrap-store.sh — Idempotent, safe Stellereum store bootstrap helper
#
# Automates snapshot download, optional/required SHA-256 verification,
# clean systemd unit + stell-node-guard.timer fencing, zero-process check,
# timestamped backup of stale data/, stale snap* cleanup, and durable safety
# record re-initialization (`safety-reset` + `safety-init`) for both fresh
# nodes and stale/lagging/quarantined nodes.
#
# Usage:
#   scripts/auto-bootstrap-store.sh --home DIR [OPTIONS]
#   scripts/auto-bootstrap-store.sh              (inside node home with data/store + keys + env.*)
#
# Options:
#   --home DIR              Node home directory (required unless auto-detected
#                           in $PWD via data/store + keys + env.*)
#   --snapshot-url URL      Snapshot archive URL
#                           (default: https://rpc.stellereum.org/snapshot/latest.tar.zst)
#   --sha256-url URL        SHA-256 manifest URL (default: <snapshot-url>.sha256;
#                           HTTP 200 verifies before extract, HTTP 404 warns and
#                           proceeds unless --require-sha256 is set)
#   --require-sha256        Fail closed if SHA-256 manifest is missing/unavailable
#   --cosign-sig-url URL    Cosign .sig URL for the snapshot archive (requires
#                           --cosign-pem-url unless --require-cosign defaults both
#                           from <snapshot-url>.sig/.pem)
#   --cosign-pem-url URL    Cosign .pem certificate URL for the snapshot archive
#   --require-cosign        Require cosign verification via verify-cosign-artifact.sh
#                           (defaults URLs to <snapshot-url>.sig/.pem if omitted)
#   --binary PATH           Path to stellereum binary (default: $HOME_DIR/stellereum,
#                           ./stellereum/target/release/stellereum, or PATH)
#   --keys-dir DIR          Keys directory containing validator.key
#                           (default: $HOME_DIR/keys)
#   --shard N               Shard ID passed to safety-init (default: 0)
#   --refresh-if-stale      Backup and replace an existing data/store
#   --force                 Same as --refresh-if-stale (replace existing data/store)
#   --backup-dir DIR        Directory to store data.bak-bootstrap-<ts>
#                           (default: $HOME_DIR)
#   --no-backup             Delete existing data/ instead of backing it up
#                           (requires --refresh-if-stale or --force)
#   --systemd-unit UNIT     Systemd unit to mask/stop cleanly during extract +
#                           safety-reset/safety-init, pausing stell-node-guard.timer
#                           and unmasking/starting afterwards
#   --user-systemd          Use `systemctl --user` instead of system `systemctl`
#   --env-file PATH         Source env file safely (STELL_KEY_PASSPHRASE,
#                           STELL_CHAIN_ID, etc.) without leaking secrets
#   --dry-run               Print every step without mutating disk or services
#   -h, --help              Show this help
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

HOME_DIR=""
SNAPSHOT_URL="https://rpc.stellereum.org/snapshot/latest.tar.zst"
SHA256_URL=""
SHA256_URL_EXPLICIT=0
REQUIRE_SHA256=0
COSIGN_SIG_URL=""
COSIGN_SIG_URL_EXPLICIT=0
COSIGN_PEM_URL=""
COSIGN_PEM_URL_EXPLICIT=0
REQUIRE_COSIGN="${STELL_REQUIRE_COSIGN:-0}"
BINARY=""
BINARY_EXPLICIT=0
KEYS_DIR=""
SHARD="0"
REFRESH_IF_STALE=0
FORCE=0
BACKUP_DIR=""
NO_BACKUP=0
SYSTEMD_UNIT=""
USER_SYSTEMD=0
ENV_FILE=""
ENV_FILE_EXPLICIT=0
DRY_RUN=0
STOP_TIMEOUT="${STELL_STOP_TIMEOUT:-300}"
GUARD_TIMER="${STELL_GUARD_UNIT:-stell-node-guard.timer}"
GUARD_SERVICE="${GUARD_TIMER%.timer}.service"

log()  { printf '\033[1;34m[auto-bootstrap-store]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,/^# ====/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'
}

resolve_abs() {
    local p="$1"
    if command -v realpath >/dev/null 2>&1; then
        realpath -m "$p"
    elif [[ "$p" = /* ]]; then
        printf '%s' "$p"
    else
        printf '%s/%s' "$PWD" "$p"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --home) HOME_DIR="${2:?--home requires a directory}"; shift 2 ;;
        --home=*) HOME_DIR="${1#--home=}"; shift ;;
        --snapshot-url) SNAPSHOT_URL="${2:?--snapshot-url requires a URL}"; shift 2 ;;
        --snapshot-url=*) SNAPSHOT_URL="${1#--snapshot-url=}"; shift ;;
        --sha256-url) SHA256_URL="${2:?--sha256-url requires a URL}"; SHA256_URL_EXPLICIT=1; shift 2 ;;
        --sha256-url=*) SHA256_URL="${1#--sha256-url=}"; SHA256_URL_EXPLICIT=1; shift ;;
        --require-sha256) REQUIRE_SHA256=1; shift ;;
        --cosign-sig-url) COSIGN_SIG_URL="${2:?--cosign-sig-url requires a URL}"; COSIGN_SIG_URL_EXPLICIT=1; shift 2 ;;
        --cosign-sig-url=*) COSIGN_SIG_URL="${1#--cosign-sig-url=}"; COSIGN_SIG_URL_EXPLICIT=1; shift ;;
        --cosign-pem-url) COSIGN_PEM_URL="${2:?--cosign-pem-url requires a URL}"; COSIGN_PEM_URL_EXPLICIT=1; shift 2 ;;
        --cosign-pem-url=*) COSIGN_PEM_URL="${1#--cosign-pem-url=}"; COSIGN_PEM_URL_EXPLICIT=1; shift ;;
        --require-cosign) REQUIRE_COSIGN=1; shift ;;
        --binary) BINARY="${2:?--binary requires a path}"; BINARY_EXPLICIT=1; shift 2 ;;
        --binary=*) BINARY="${1#--binary=}"; BINARY_EXPLICIT=1; shift ;;
        --keys-dir) KEYS_DIR="${2:?--keys-dir requires a directory}"; shift 2 ;;
        --keys-dir=*) KEYS_DIR="${1#--keys-dir=}"; shift ;;
        --shard) SHARD="${2:?--shard requires an integer}"; shift 2 ;;
        --shard=*) SHARD="${1#--shard=}"; shift ;;
        --refresh-if-stale) REFRESH_IF_STALE=1; shift ;;
        --force) FORCE=1; shift ;;
        --backup-dir) BACKUP_DIR="${2:?--backup-dir requires a directory}"; shift 2 ;;
        --backup-dir=*) BACKUP_DIR="${1#--backup-dir=}"; shift ;;
        --no-backup) NO_BACKUP=1; shift ;;
        --systemd-unit) SYSTEMD_UNIT="${2:?--systemd-unit requires a unit name}"; shift 2 ;;
        --systemd-unit=*) SYSTEMD_UNIT="${1#--systemd-unit=}"; shift ;;
        --user-systemd) USER_SYSTEMD=1; shift ;;
        --env-file) ENV_FILE="${2:?--env-file requires a path}"; ENV_FILE_EXPLICIT=1; shift 2 ;;
        --env-file=*) ENV_FILE="${1#--env-file=}"; ENV_FILE_EXPLICIT=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'auto-bootstrap-store.sh: unknown argument %s (try --help)\n' "$1" >&2; exit 2 ;;
    esac
done

if ! [[ "$SHARD" =~ ^[0-9]+$ ]]; then
    die "--shard must be an unsigned integer (got '$SHARD')"
fi
if ! [[ "$STOP_TIMEOUT" =~ ^[0-9]+$ ]]; then
    die "STELL_STOP_TIMEOUT must be an unsigned integer (got '$STOP_TIMEOUT')"
fi
if [[ -z "$SNAPSHOT_URL" ]]; then
    die "--snapshot-url cannot be empty"
fi

if [[ "$SHA256_URL_EXPLICIT" == "0" ]]; then
    SHA256_URL="${SNAPSHOT_URL}.sha256"
elif [[ -z "$SHA256_URL" && "$REQUIRE_SHA256" == "1" ]]; then
    die "--require-sha256 cannot be used with an empty --sha256-url"
fi

case "$REQUIRE_COSIGN" in
    0|1) ;;
    *) die "STELL_REQUIRE_COSIGN must be 0 or 1 (got '$REQUIRE_COSIGN')" ;;
esac

if [[ "$COSIGN_SIG_URL_EXPLICIT" == "1" && -z "$COSIGN_SIG_URL" ]]; then
    die "--cosign-sig-url cannot be empty"
fi
if [[ "$COSIGN_PEM_URL_EXPLICIT" == "1" && -z "$COSIGN_PEM_URL" ]]; then
    die "--cosign-pem-url cannot be empty"
fi
if [[ "$COSIGN_SIG_URL_EXPLICIT" == "1" && "$COSIGN_PEM_URL_EXPLICIT" == "0" ]]; then
    if [[ "$REQUIRE_COSIGN" == "1" ]]; then
        COSIGN_PEM_URL="${SNAPSHOT_URL}.pem"
    else
        die "--cosign-sig-url requires --cosign-pem-url"
    fi
fi
if [[ "$COSIGN_PEM_URL_EXPLICIT" == "1" && "$COSIGN_SIG_URL_EXPLICIT" == "0" ]]; then
    if [[ "$REQUIRE_COSIGN" == "1" ]]; then
        COSIGN_SIG_URL="${SNAPSHOT_URL}.sig"
    else
        die "--cosign-pem-url requires --cosign-sig-url"
    fi
fi

USE_COSIGN=0
if [[ "$REQUIRE_COSIGN" == "1" || ( -n "$COSIGN_SIG_URL" && -n "$COSIGN_PEM_URL" ) ]]; then
    USE_COSIGN=1
    if [[ -z "$COSIGN_SIG_URL" ]]; then
        COSIGN_SIG_URL="${SNAPSHOT_URL}.sig"
    fi
    if [[ -z "$COSIGN_PEM_URL" ]]; then
        COSIGN_PEM_URL="${SNAPSHOT_URL}.pem"
    fi
fi
COSIGN_VERIFIER="$SCRIPT_DIR/verify-cosign-artifact.sh"

# Auto-detect --home from $PWD if omitted
if [[ -z "$HOME_DIR" ]]; then
    if [[ -d "$PWD/data/store" && -d "$PWD/keys" ]] && \
       { compgen -G "$PWD/env.*" >/dev/null || [[ -f "$PWD/node.env" ]]; }; then
        HOME_DIR="$PWD"
        log "auto-detected node home at $HOME_DIR"
    else
        die "--home DIR is required (could not auto-detect data/store + keys + env.* in $PWD)"
    fi
fi

HOME_DIR="$(resolve_abs "$HOME_DIR")"
DATA_DIR="$HOME_DIR/data"
STORE_DIR="$DATA_DIR/store"

if [[ -z "$KEYS_DIR" ]]; then
    KEYS_DIR="$HOME_DIR/keys"
else
    KEYS_DIR="$(resolve_abs "$KEYS_DIR")"
fi

if [[ -n "$BACKUP_DIR" ]]; then
    BACKUP_DIR="$(resolve_abs "$BACKUP_DIR")"
fi

# Validate required CLI tools
for tool in curl tar zstd; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        die "required tool '$tool' not found in PATH"
    fi
done
if [[ -n "$SHA256_URL" ]] && ! command -v sha256sum >/dev/null 2>&1; then
    die "required tool 'sha256sum' not found in PATH"
fi
if [[ "$USE_COSIGN" == "1" ]]; then
    if [[ ! -x "$COSIGN_VERIFIER" ]]; then
        die "cosign verifier script not found or not executable: $COSIGN_VERIFIER"
    fi
    if ! command -v cosign >/dev/null 2>&1; then
        if [[ "$DRY_RUN" == "1" ]]; then
            warn "cosign not found in PATH (would fail in a live run with --require-cosign / cosign URLs)"
        else
            die "required tool 'cosign' not found in PATH"
        fi
    fi
fi

# Locate stellereum binary
if [[ -z "$BINARY" ]]; then
    for cand in \
        "$HOME_DIR/stellereum" \
        "$ROOT_DIR/target/release/stellereum" \
        "./stellereum/target/release/stellereum" \
        "$ROOT_DIR/stellereum/target/release/stellereum" \
        "$(command -v stellereum 2>/dev/null || true)"; do
        if [[ -n "$cand" && -x "$cand" ]]; then
            BINARY="$(resolve_abs "$cand")"
            break
        fi
    done
else
    BINARY="$(resolve_abs "$BINARY")"
fi

if [[ -z "$BINARY" || ! -x "$BINARY" ]]; then
    if [[ "$DRY_RUN" == "1" && "$BINARY_EXPLICIT" == "0" ]]; then
        warn "stellereum binary not found automatically (would require --binary PATH in a live run)"
        BINARY="<stellereum-binary>"
    else
        die "stellereum binary not found or not executable: ${BINARY:-<none>} (pass --binary PATH)"
    fi
fi

# Validate or auto-detect env file
detect_env_file() {
    local cand
    if [[ -f "$HOME_DIR/node.env" ]]; then
        printf '%s' "$HOME_DIR/node.env"
        return 0
    fi
    if [[ -f "$HOME_DIR/env.observer" ]]; then
        printf '%s' "$HOME_DIR/env.observer"
        return 0
    fi
    local -a matches=()
    for cand in "$HOME_DIR"/env.*; do
        [[ -e "$cand" && -f "$cand" ]] || continue
        case "${cand##*/}" in
            *.bak*|*.old|*.tmp*) continue ;;
            *) matches+=("$cand") ;;
        esac
    done
    if [[ "${#matches[@]}" -eq 1 ]]; then
        printf '%s' "${matches[0]}"
        return 0
    fi
    return 1
}

if [[ "$ENV_FILE_EXPLICIT" == "1" ]]; then
    ENV_FILE="$(resolve_abs "$ENV_FILE")"
    [[ -f "$ENV_FILE" && -r "$ENV_FILE" ]] || die "--env-file not found or unreadable: $ENV_FILE"
else
    ENV_FILE="$(detect_env_file || true)"
fi

source_env_safely() {
    local file="$1"
    local was_x=0
    [[ "$-" == *x* ]] && was_x=1
    set +x
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
    (( was_x )) && set -x
    local p_state="unset"
    if [[ -n "${STELL_KEY_PASSPHRASE:-}" ]]; then
        p_state="set"
    fi
    log "sourced env file $file (STELL_CHAIN_ID=${STELL_CHAIN_ID:-unset}, passphrase=$p_state)"
}

# Validate keys directory
if [[ ! -d "$KEYS_DIR" || ! -f "$KEYS_DIR/validator.key" ]]; then
    if [[ "$DRY_RUN" == "1" ]]; then
        warn "keys directory or $KEYS_DIR/validator.key does not exist yet (required for safety-init in a live run)"
    else
        die "keys directory must exist and contain validator.key: $KEYS_DIR"
    fi
fi

stctl() {
    if [[ "$USER_SYSTEMD" == "1" ]]; then
        systemctl --user "$@"
    else
        systemctl "$@"
    fi
}

systemd_is_active_bus() {
    command -v systemctl >/dev/null 2>&1 || return 1
    stctl list-units --no-legend >/dev/null 2>&1
}

find_store_pids() {
    local home_real data_real store_real
    home_real="$(resolve_abs "$HOME_DIR")"
    data_real="$(resolve_abs "$DATA_DIR")"
    store_real="$(resolve_abs "$STORE_DIR")"

    local pid_dir pid argv0 cmdline cwd_path fd_link fd_target matched
    for pid_dir in /proc/[0-9]*; do
        [[ -d "$pid_dir" ]] || continue
        pid="${pid_dir##*/}"
        [[ "$pid" == "$$" || "$pid" == "$PPID" ]] && continue
        [[ -r "$pid_dir/cmdline" ]] || continue

        argv0="$(tr '\0' '\n' < "$pid_dir/cmdline" 2>/dev/null | head -n 1 || true)"
        [[ "${argv0##*/}" == "stellereum" ]] || continue

        cmdline="$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)"
        [[ " $cmdline " == *" run "* ]] || continue

        matched=0
        cwd_path="$(readlink -f "$pid_dir/cwd" 2>/dev/null || true)"
        if [[ -n "$cwd_path" ]]; then
            case "$cwd_path" in
                "$home_real"|"$home_real"/*|"$data_real"|"$data_real"/*|"$store_real"|"$store_real"/*)
                    matched=1
                    ;;
            esac
        fi

        if [[ "$matched" == "0" ]]; then
            case " $cmdline " in
                *" $store_real "*|*"=$store_real "*|*" $store_real/"*|*"=$store_real/"*|\
                *" $data_real "*|*"=$data_real "*|*" $data_real/"*|*"=$data_real/"*|\
                *" $home_real/"*|*"=$home_real/"*|*" $home_real "*)
                    matched=1
                    ;;
            esac
        fi

        if [[ "$matched" == "0" && -d "$pid_dir/fd" ]]; then
            for fd_link in "$pid_dir"/fd/*; do
                [[ -L "$fd_link" ]] || continue
                fd_target="$(readlink -f "$fd_link" 2>/dev/null || true)"
                case "$fd_target" in
                    "$store_real"|"$store_real"/*|"$data_real"|"$data_real"/*)
                        matched=1
                        break
                        ;;
                esac
            done
        fi

        if [[ "$matched" == "1" ]]; then
            printf '%s\n' "$pid"
        fi
    done
}

# Check existing store guard
REPLACING_EXISTING=0
if [[ -e "$STORE_DIR" ]]; then
    if [[ "$REFRESH_IF_STALE" == "0" && "$FORCE" == "0" ]]; then
        log "existing store found at $STORE_DIR; refusing to replace without --refresh-if-stale or --force (nothing changed)"
        exit 0
    fi
    REPLACING_EXISTING=1
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_BASE="${BACKUP_DIR:-$HOME_DIR}"
BACKUP_PATH="$BACKUP_BASE/data.bak-bootstrap-$TS"
if [[ -e "$BACKUP_PATH" ]]; then
    BACKUP_PATH="${BACKUP_PATH}.$$"
fi

# Dry-run plan (zero mutations, zero service stops)
if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY RUN — no disk writes, downloads, or service changes will be performed"
    log "  home:         $HOME_DIR"
    log "  data dir:     $DATA_DIR (store_exists=$([[ -e "$STORE_DIR" ]] && echo yes || echo no), replace=$REPLACING_EXISTING)"
    log "  keys dir:     $KEYS_DIR"
    log "  shard:        $SHARD"
    log "  binary:       $BINARY"
    log "  snapshot url: $SNAPSHOT_URL"
    log "  sha256 url:   ${SHA256_URL:-<disabled>} (require=$REQUIRE_SHA256)"
    log "  cosign:       $([[ "$USE_COSIGN" == "1" ]] && echo "enabled (require=$REQUIRE_COSIGN, sig=$COSIGN_SIG_URL, pem=$COSIGN_PEM_URL)" || echo "<disabled>")"
    log "  env file:     ${ENV_FILE:-<none>}"
    if [[ -n "$ENV_FILE" ]]; then
        log "step: safely source env file $ENV_FILE (without printing secret values)"
    fi
    log "step: download snapshot from $SNAPSHOT_URL to a temporary staging file"
    if [[ -n "$SHA256_URL" ]]; then
        log "step: fetch SHA-256 from $SHA256_URL (HTTP 200 -> verify before extract; HTTP 404 -> $([[ "$REQUIRE_SHA256" == "1" ]] && echo 'fail (--require-sha256)' || echo 'warn and proceed'))"
    fi
    if [[ "$USE_COSIGN" == "1" ]]; then
        log "step: fetch cosign .sig ($COSIGN_SIG_URL) and .pem ($COSIGN_PEM_URL) and run '$COSIGN_VERIFIER --require'"
    fi
    if [[ -n "$SYSTEMD_UNIT" ]]; then
        if systemd_is_active_bus; then
            local_scope="system"
            [[ "$USER_SYSTEMD" == "1" ]] && local_scope="user"
            unit_load="$(stctl show -p LoadState --value "$SYSTEMD_UNIT" 2>/dev/null || echo unknown)"
            guard_active="$(stctl is-active "$GUARD_TIMER" 2>/dev/null || echo inactive)"
            log "step: [systemd $local_scope] pause $GUARD_TIMER (currently $guard_active), mask & stop $SYSTEMD_UNIT (LoadState=$unit_load)"
        else
            warn "systemctl is not active; systemd pause/stop/start steps would be skipped"
        fi
    fi
    mapfile -t running_pids < <(find_store_pids)
    if [[ "${#running_pids[@]}" -gt 0 ]]; then
        log "step: confirm zero running 'stellereum run' processes for $STORE_DIR (currently running: ${#running_pids[@]} [${running_pids[*]}])"
    else
        log "step: confirm zero running 'stellereum run' processes for $STORE_DIR (currently running: 0)"
    fi
    if [[ "$REPLACING_EXISTING" == "1" || -d "$DATA_DIR" ]]; then
        if [[ "$NO_BACKUP" == "1" ]]; then
            log "step: remove existing $DATA_DIR (--no-backup)"
        elif [[ -d "$DATA_DIR" ]]; then
            log "step: backup existing $DATA_DIR -> $BACKUP_PATH"
        fi
    fi
    log "step: create $DATA_DIR (0700) and extract snapshot with 'tar -I \"zstd -d\" -xf ... -C $DATA_DIR'"
    log "step: validate $STORE_DIR exists and remove stale snap* files under $DATA_DIR/store*"
    log "step: run '$BINARY safety-reset --store-dir $STORE_DIR --i-fenced-all-signers'"
    log "step: run '$BINARY safety-init --store-dir $STORE_DIR --keys-dir $KEYS_DIR --shard $SHARD --i-fenced-all-signers'"
    if [[ -n "$SYSTEMD_UNIT" ]] && systemd_is_active_bus; then
        log "step: unmask & start $SYSTEMD_UNIT and re-enable/start $GUARD_TIMER"
    fi
    ok "DRY RUN complete; nothing was modified"
    exit 0
fi

# Live execution
if [[ -n "$ENV_FILE" ]]; then
    source_env_safely "$ENV_FILE"
fi

mkdir -p "$HOME_DIR"
chmod 700 "$HOME_DIR"

WORK_DIR="$(mktemp -d "$HOME_DIR/.bootstrap-work.XXXXXX")"
ARCHIVE_FILE="$WORK_DIR/snapshot.tar.zst"
SHA_FILE="$WORK_DIR/snapshot.tar.zst.sha256"
COSIGN_SIG_FILE="$WORK_DIR/snapshot.tar.zst.sig"
COSIGN_PEM_FILE="$WORK_DIR/snapshot.tar.zst.pem"

SYSTEMD_ACTIVE=0
UNIT_MASKED_BY_US=0
GUARD_PAUSED_BY_US=0
GUARD_WAS_ACTIVE=0
DATA_MUTATED=0

cleanup() {
    local rc=$?
    if [[ -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
    if [[ "$rc" -ne 0 && "$DATA_MUTATED" == "0" ]]; then
        # Safe rollback of service/guard state if we never touched data/
        if [[ "$UNIT_MASKED_BY_US" == "1" ]]; then
            stctl unmask --runtime "$SYSTEMD_UNIT" >/dev/null 2>&1 || stctl unmask "$SYSTEMD_UNIT" >/dev/null 2>&1 || true
        fi
        if [[ "$GUARD_PAUSED_BY_US" == "1" && "$GUARD_WAS_ACTIVE" == "1" ]]; then
            stctl start "$GUARD_TIMER" >/dev/null 2>&1 || true
        fi
    elif [[ "$rc" -ne 0 && "$DATA_MUTATED" == "1" ]]; then
        warn "bootstrap failed AFTER modifying $DATA_DIR; $SYSTEMD_UNIT remains stopped/masked and $GUARD_TIMER remains paused for safety"
        if [[ "$NO_BACKUP" == "0" && -d "$BACKUP_PATH" ]]; then
            warn "previous data directory backup is preserved at: $BACKUP_PATH"
        fi
    fi
}
trap cleanup EXIT

# 1. Download snapshot and verify SHA-256 BEFORE stopping any running unit or touching data/
log "downloading snapshot from $SNAPSHOT_URL..."
curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$ARCHIVE_FILE" "$SNAPSHOT_URL" \
    || die "failed to download snapshot from $SNAPSHOT_URL"

if [[ -n "$SHA256_URL" ]]; then
    log "checking SHA-256 manifest at $SHA256_URL..."
    sha_http_code="$(curl -sS -L --connect-timeout 15 -w '%{http_code}' -o "$SHA_FILE" "$SHA256_URL" || true)"
    if [[ "$sha_http_code" == "200" ]]; then
        expected_sha="$(awk 'NF>=1 {print tolower($1); exit}' "$SHA_FILE")"
        if ! [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
            die "invalid SHA-256 checksum format returned by $SHA256_URL"
        fi
        actual_sha="$(sha256sum "$ARCHIVE_FILE" | awk '{print tolower($1)}')"
        if [[ "$actual_sha" != "$expected_sha" ]]; then
            die "snapshot SHA-256 mismatch: expected=$expected_sha actual=$actual_sha"
        fi
        ok "snapshot SHA-256 verified ($actual_sha)"
    elif [[ "$sha_http_code" == "404" ]]; then
        rm -f "$SHA_FILE"
        if [[ "$REQUIRE_SHA256" == "1" ]]; then
            die "SHA-256 manifest returned HTTP 404 at $SHA256_URL and --require-sha256 is set"
        fi
        warn "SHA-256 manifest returned HTTP 404 at $SHA256_URL; proceeding without checksum verification"
    else
        rm -f "$SHA_FILE"
        if [[ "$REQUIRE_SHA256" == "1" ]]; then
            die "failed to fetch SHA-256 manifest at $SHA256_URL (HTTP ${sha_http_code:-error}) and --require-sha256 is set"
        fi
        warn "could not fetch SHA-256 manifest at $SHA256_URL (HTTP ${sha_http_code:-error}); proceeding without checksum verification"
    fi
fi

if [[ "$USE_COSIGN" == "1" ]]; then
    log "fetching cosign signature ($COSIGN_SIG_URL) and certificate ($COSIGN_PEM_URL)..."
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$COSIGN_SIG_FILE" "$COSIGN_SIG_URL" \
        || die "failed to download cosign signature from $COSIGN_SIG_URL"
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$COSIGN_PEM_FILE" "$COSIGN_PEM_URL" \
        || die "failed to download cosign certificate from $COSIGN_PEM_URL"
    "$COSIGN_VERIFIER" --require --sig "$COSIGN_SIG_FILE" --pem "$COSIGN_PEM_FILE" "$ARCHIVE_FILE" \
        || die "cosign artifact verification failed for downloaded snapshot"
    ok "snapshot cosign signature verified"
fi

log "verifying downloaded archive integrity (zstd -t)..."
zstd -t "$ARCHIVE_FILE" >/dev/null 2>&1 || die "downloaded snapshot failed zstd integrity check (truncated/corrupt)"

# 2. Stop/mask systemd unit and pause guard if requested and systemctl is active
if [[ -n "$SYSTEMD_UNIT" ]]; then
    if systemd_is_active_bus; then
        SYSTEMD_ACTIVE=1
        unit_load="$(stctl show -p LoadState --value "$SYSTEMD_UNIT" 2>/dev/null || echo "not-found")"
        if [[ "$unit_load" == "not-found" ]]; then
            die "systemd unit '$SYSTEMD_UNIT' not found"
        fi
        if stctl is-active --quiet "$GUARD_TIMER" 2>/dev/null; then
            GUARD_WAS_ACTIVE=1
            log "pausing $GUARD_TIMER..."
            stctl stop "$GUARD_TIMER"
            GUARD_PAUSED_BY_US=1
        fi
        if stctl is-active --quiet "$GUARD_SERVICE" 2>/dev/null; then
            log "stopping active $GUARD_SERVICE..."
            stctl stop "$GUARD_SERVICE" || true
        fi
        log "masking and stopping $SYSTEMD_UNIT..."
        if [[ "$unit_load" != "masked" ]]; then
            if stctl mask --runtime "$SYSTEMD_UNIT" >/dev/null 2>&1; then
                UNIT_MASKED_BY_US=1
            fi
        fi
        stctl stop "$SYSTEMD_UNIT"

        deadline=$(( $(date +%s) + STOP_TIMEOUT ))
        while :; do
            unit_state="$(stctl is-active "$SYSTEMD_UNIT" 2>/dev/null || true)"
            mapfile -t running_pids < <(find_store_pids)
            case "$unit_state" in
                active|activating|deactivating|reloading) ;;
                *)
                    if [[ "${#running_pids[@]}" -eq 0 ]]; then
                        break
                    fi
                    ;;
            esac
            if [[ "$(date +%s)" -ge "$deadline" ]]; then
                die "timed out after ${STOP_TIMEOUT}s waiting for $SYSTEMD_UNIT (state=${unit_state:-unknown}) and store processes (${running_pids[*]:-none}) to stop"
            fi
            sleep 1
        done
        ok "$SYSTEMD_UNIT stopped cleanly and masked"
    else
        warn "systemctl is not active; skipping --systemd-unit handling for $SYSTEMD_UNIT"
    fi
fi

# 3. Confirm zero running `stellereum run` processes using that store before touching data/
mapfile -t running_pids < <(find_store_pids)
if [[ "${#running_pids[@]}" -gt 0 ]]; then
    die "refusing to modify $STORE_DIR: running 'stellereum run' process(es) detected (PIDs: ${running_pids[*]})"
fi
ok "confirmed zero running 'stellereum run' processes using $STORE_DIR"

# 4. Backup or remove existing data/
if [[ -d "$DATA_DIR" ]]; then
    if [[ "$REPLACING_EXISTING" == "1" ]]; then
        DATA_MUTATED=1
        if [[ "$NO_BACKUP" == "1" ]]; then
            log "removing existing $DATA_DIR (--no-backup)..."
            rm -rf "$DATA_DIR"
        else
            if [[ -n "$BACKUP_DIR" ]]; then
                mkdir -p "$BACKUP_DIR"
                chmod 700 "$BACKUP_DIR"
            fi
            log "backing up existing $DATA_DIR -> $BACKUP_PATH..."
            mv "$DATA_DIR" "$BACKUP_PATH"
        fi
    elif [[ -n "$(ls -A "$DATA_DIR" 2>/dev/null || true)" ]]; then
        # data/ exists without data/store (e.g. empty or partial dir); treat non-empty only if replacing?
        # Fresh node dirs from join-testnet.sh create empty data/; empty dir is safe to extract into.
        DATA_MUTATED=1
    fi
fi

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"
DATA_MUTATED=1

# 5. Extract snapshot, normalize layout if needed, remove stale snap* files
log "extracting snapshot into $DATA_DIR..."
if ! tar -I 'zstd -d' -xf "$ARCHIVE_FILE" -C "$DATA_DIR"; then
    die "snapshot extraction failed"
fi

if [[ ! -d "$STORE_DIR" && -d "$DATA_DIR/data/store" ]]; then
    log "normalizing nested data/store layout from snapshot archive..."
    mv "$DATA_DIR/data/"* "$DATA_DIR/"
    rmdir "$DATA_DIR/data" 2>/dev/null || true
fi

[[ -d "$STORE_DIR" ]] || die "extracted snapshot does not contain $STORE_DIR"
rm -f "$DATA_DIR"/store*/snap* 2>/dev/null || true
ok "snapshot extracted to $STORE_DIR and stale snap* files removed"

# 6. Re-verify zero running `stellereum run` processes immediately before safety-reset / safety-init
mapfile -t running_pids < <(find_store_pids)
if [[ "${#running_pids[@]}" -gt 0 ]]; then
    die "refusing to run safety-reset/safety-init: running 'stellereum run' process(es) detected (PIDs: ${running_pids[*]})"
fi

log "running safety-reset on $STORE_DIR..."
if ! reset_out="$("$BINARY" safety-reset --store-dir "$STORE_DIR" --i-fenced-all-signers 2>&1)"; then
    printf '%s\n' "$reset_out" >&2
    die "safety-reset on $STORE_DIR failed (is $BINARY the current release?)"
fi

log "running safety-init on $STORE_DIR (keys=$KEYS_DIR, shard=$SHARD)..."
if ! "$BINARY" safety-init --store-dir "$STORE_DIR" --keys-dir "$KEYS_DIR" \
    --shard "$SHARD" --i-fenced-all-signers; then
    die "safety-init for this node's key failed; refusing to leave a node that cannot vote"
fi
ok "safety record initialized for $STORE_DIR (shard=$SHARD)"

# 7. Unmask/start systemd unit and re-enable guard if we paused/masked them
if [[ "$SYSTEMD_ACTIVE" == "1" ]]; then
    if [[ "$UNIT_MASKED_BY_US" == "1" ]]; then
        log "unmasking $SYSTEMD_UNIT..."
        stctl unmask --runtime "$SYSTEMD_UNIT" >/dev/null 2>&1 || stctl unmask "$SYSTEMD_UNIT" >/dev/null 2>&1 || true
        UNIT_MASKED_BY_US=0
    fi
    log "starting $SYSTEMD_UNIT..."
    stctl start "$SYSTEMD_UNIT"
    if [[ "$GUARD_PAUSED_BY_US" == "1" && "$GUARD_WAS_ACTIVE" == "1" ]]; then
        log "re-enabling $GUARD_TIMER..."
        stctl start "$GUARD_TIMER"
        GUARD_PAUSED_BY_US=0
    fi
    ok "$SYSTEMD_UNIT started and guard restored"
fi
