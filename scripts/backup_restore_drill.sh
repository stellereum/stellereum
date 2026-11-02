#!/usr/bin/env bash
# backup_restore_drill.sh — dry-run restore drill: decrypt an off-host image
# produced by scripts/backup_offhost.sh into a TEMP dir, verify its shipped
# manifest, then prove boot-readability by CALLING scripts/backup_verify.sh
# on the restored copy (logic is reused, not duplicated here).
#
# NON-DESTRUCTIVE BY CONSTRUCTION:
#   - the backup source is only ever READ (decrypt reads the .enc file);
#   - the restore target is always a fresh temp dir OUTSIDE any live data
#     dir (guarded, fails closed); nothing is ever restored over a live path;
#   - --dry-run prints the plan and changes nothing on disk.
#
# Usage:
#   scripts/backup_restore_drill.sh --backup-dir <image-dir> [--passphrase-file PATH] [--dry-run]
#   scripts/backup_restore_drill.sh --archive <image.tar.gz.enc> --passphrase-file <f>
#
# flags: --backup-dir PATH | --archive PATH (exactly one, required)
#        [--passphrase-file PATH] [--work-dir PATH] [--keep-work-dir]
#        [--use-age] [--dry-run]
#
set -euo pipefail

BACKUP_DIR=""
ARCHIVE=""
PP_FILE=""
WORK_DIR=""
KEEP_WORK=0
USE_AGE=0
DRY_RUN=0

usage() {
    sed -n '2,/^#$/p' "$0" | sed 's/^# \{0,1\}//'
    echo "flags: --backup-dir PATH | --archive PATH (exactly one, required)"
    echo "       [--passphrase-file PATH] [--work-dir PATH] [--keep-work-dir]"
    echo "       [--use-age] [--dry-run]"
}

fail() { echo "[backup_restore_drill] FAIL: $1" >&2; exit 1; }
pass() { echo "[backup_restore_drill] PASS: $1"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --backup-dir) BACKUP_DIR="${2:-}"; shift 2 ;;
        --archive) ARCHIVE="${2:-}"; shift 2 ;;
        --passphrase-file) PP_FILE="${2:-}"; shift 2 ;;
        --work-dir) WORK_DIR="${2:-}"; shift 2 ;;
        --keep-work-dir) KEEP_WORK=1; shift ;;
        --use-age) USE_AGE=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[backup_restore_drill] FATAL: unknown arg '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -n "$BACKUP_DIR" || -n "$ARCHIVE" ]] || { echo "[backup_restore_drill] FATAL: one of --backup-dir or --archive is required" >&2; exit 2; }
[[ -z "$BACKUP_DIR" || -z "$ARCHIVE" ]] || { echo "[backup_restore_drill] FATAL: --backup-dir and --archive are mutually exclusive" >&2; exit 2; }

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
VERIFY="$SCRIPT_DIR/backup_verify.sh"
[[ -x "$VERIFY" ]] || { echo "[backup_restore_drill] FATAL: verifier missing/not executable: $VERIFY" >&2; exit 2; }

# Resolve the encrypted artifact. In dry-run the source may not exist yet:
# print the plan instead of failing (plan changes nothing on disk).
SRC=""
if [[ -n "$BACKUP_DIR" ]]; then
    if [[ "$DRY_RUN" -eq 1 && ! -d "$BACKUP_DIR" ]]; then
        SRC="$(realpath -m "$BACKUP_DIR")/<image>.tar.gz.enc (not present yet — plan only)"
    else
        [[ -d "$BACKUP_DIR" ]] || { echo "[backup_restore_drill] FATAL: backup dir missing: $BACKUP_DIR" >&2; exit 2; }
        BACKUP_DIR="$(realpath "$BACKUP_DIR")"
        SRC="$(find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz.enc' | LC_ALL=C sort | head -1)"
        [[ -n "$SRC" ]] || { echo "[backup_restore_drill] FATAL: no *.tar.gz.enc in $BACKUP_DIR" >&2; exit 2; }
    fi
else
    if [[ "$DRY_RUN" -eq 1 && ! -f "$ARCHIVE" ]]; then
        SRC="$(realpath -m "$ARCHIVE") (not present yet — plan only)"
    else
        [[ -f "$ARCHIVE" ]] || { echo "[backup_restore_drill] FATAL: archive missing: $ARCHIVE" >&2; exit 2; }
        SRC="$(realpath "$ARCHIVE")"
    fi
fi

# Work dir: fresh temp by default; never inside the backup source.
if [[ -z "$WORK_DIR" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
        WORK_DIR="<mktemp -d -t stell-drill-XXXXXX>"
    else
        WORK_DIR="$(mktemp -d -t stell-drill-XXXXXX)"
        AUTO_WORK=1
    fi
else
    AUTO_WORK=0
    if [[ "$DRY_RUN" -eq 0 ]]; then
        mkdir -p "$WORK_DIR"
        WORK_DIR="$(realpath "$WORK_DIR")"
    fi
fi
if [[ "$DRY_RUN" -eq 0 ]]; then
    case "$WORK_DIR" in
        "$BACKUP_DIR"*) fail "work dir inside backup source ($WORK_DIR)" ;;
    esac
    if [[ -n "$BACKUP_DIR" ]]; then
        case "$BACKUP_DIR" in
            "$WORK_DIR"*) fail "backup source inside work dir ($BACKUP_DIR)" ;;
        esac
    fi
fi

cleanup() {
    if [[ "$DRY_RUN" -eq 0 && "$KEEP_WORK" -eq 0 && "${AUTO_WORK:-0}" -eq 1 ]]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

plan() {
    echo "[backup_restore_drill] PLAN (dry-run, nothing decrypted/restored):"
    echo "  backup source : ${BACKUP_DIR:-$ARCHIVE}"
    echo "  enc artifact  : $SRC"
    echo "  work dir      : $WORK_DIR"
    echo "  decryptor     : $([[ "$USE_AGE" -eq 1 ]] && echo 'age -d' || echo 'openssl enc -d -aes-256-cbc -pbkdf2')"
    echo "  1. decrypt artifact -> \$WORK/image.tar.gz (read-only on backup source)"
    echo "  2. tar -xzf into \$WORK/plain/ (fresh temp dir, never a live path)"
    echo "  3. sha256sum -c manifest.sha256 inside the restored tree"
    echo "  4. call scripts/backup_verify.sh --data-dir <restored tree> (reused boot-read check)"
    echo "  5. PASS/FAIL report"
}

if [[ "$DRY_RUN" -eq 1 ]]; then plan; exit 0; fi

if [[ "$USE_AGE" -eq 1 ]]; then
    command -v age >/dev/null 2>&1 || { echo "[backup_restore_drill] FATAL: --use-age given but 'age' is not installed" >&2; exit 2; }
else
    [[ -n "$PP_FILE" ]] || { echo "[backup_restore_drill] FATAL: --passphrase-file is required for the openssl backend" >&2; exit 2; }
    [[ -f "$PP_FILE" ]] || { echo "[backup_restore_drill] FATAL: passphrase file missing: $PP_FILE" >&2; exit 2; }
fi

echo "[backup_restore_drill] backup source: ${BACKUP_DIR:-$ARCHIVE}"
echo "[backup_restore_drill] enc artifact : $SRC"
echo "[backup_restore_drill] work dir     : $WORK_DIR"

# 1. Decrypt (read-only on the backup source) into the temp work dir.
TARGZ="$WORK_DIR/image.tar.gz"
if [[ "$USE_AGE" -eq 1 ]]; then
    age --decrypt -o "$TARGZ" "$SRC"
else
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$SRC" -out "$TARGZ" -pass "file:$PP_FILE"
fi
echo "[backup_restore_drill] step 1/4 decrypted ($(du -h "$TARGZ" | cut -f1))"

# 2. Unpack into a fresh temp dir — never over a live path.
PLAIN="$WORK_DIR/plain"
mkdir -p "$PLAIN"
tar -xzf "$TARGZ" -C "$PLAIN"
echo "[backup_restore_drill] step 2/4 unpacked into temp dir"

# 3. Verify the shipped manifest inside the restored tree.
[[ -f "$PLAIN/manifest.sha256" ]] || fail "shipped manifest missing in restored tree ($PLAIN)"
( cd "$PLAIN" && sha256sum -c manifest.sha256 --quiet ) || fail "shipped manifest mismatch in restored tree"
NFILES="$(wc -l < "$PLAIN/manifest.sha256")"
pass "step 3/4 shipped manifest verified ($NFILES entries, sha256 match)"

# 4. Boot-read check: REUSE backup_verify.sh on the restored copy.
#    The drill never reimplements the check — the verifier owns that logic.
RESTORED_DATA="$PLAIN/files"
[[ -d "$RESTORED_DATA" ]] || RESTORED_DATA="$PLAIN"
echo "[backup_restore_drill] step 4/4 delegating boot-read check to scripts/backup_verify.sh"
"$VERIFY" --data-dir "$RESTORED_DATA" --work-dir "$WORK_DIR/verify"

pass "restore drill complete: image decrypts, manifest matches, backup_verify.sh green"
echo "[backup_restore_drill] drill work dir: $WORK_DIR (auto-removed unless --keep-work-dir)"
