#!/usr/bin/env bash
# backup_offhost.sh — off-host backup: stage (copy-only) a live node data dir
# + node.yaml + keys INVENTORY (file names + modes only, never key contents),
# write a sha256 manifest, tar + encrypt the image, offer an upload hook, and
# prune old images by retention (keep-N).
#
# ENCRYPTION CHOICE (checked on this host, 2026-11-02):
#   - `age` is PREFERRED when present (public-key, no shared secret on disk),
#     but it is NOT installed here (`command -v age` -> absent).
#   - `openssl enc` IS present (OpenSSL 3.6.2) and is therefore the ACTIVE
#     backend: `openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt`.
#     Install age to use the preferred path (`--age-recipient`); the openssl
#     path remains as fallback. The script auto-selects and prints which
#     backend it used.
#
# NON-DESTRUCTIVE BY CONSTRUCTION:
#   - live dirs are only ever READ (cp -a out, never move/rm/write);
#   - staging/output live OUTSIDE the data dir (guarded, fails closed);
#   - upload defaults to DRY-RUN (nothing leaves the host); a real copy to
#     --upload-target requires the explicit --confirm-live flag, and remote
#     targets (s3://, host:path, any URI) are REFUSED — no uploader is
#     configured, so the script fails closed instead of pretending.
#
# Usage:
#   scripts/backup_offhost.sh --data-dir <path> [options]
#   scripts/backup_offhost.sh --data-dir run/cluster/node1/data --dry-run
#
# flags: --data-dir PATH (required) [--node-yaml PATH] [--out-dir PATH]
#        [--keep N] [--passphrase-file PATH] [--age-recipient RECIP]
#        [--upload-target PATH] [--confirm-live] [--dry-run]
#
set -euo pipefail

DATA_DIR=""
NODE_YAML=""
OUT_DIR="./tmp/backup-offhost"
KEEP=5
PP_FILE=""
AGE_RECIPIENT=""
UPLOAD_TARGET=""
CONFIRM_LIVE=0
DRY_RUN=0

usage() {
    sed -n '2,/^#$/p' "$0" | sed 's/^# \{0,1\}//'
    echo "flags: --data-dir PATH (required) [--node-yaml PATH] [--out-dir PATH]"
    echo "       [--keep N] [--passphrase-file PATH] [--age-recipient RECIP]"
    echo "       [--upload-target PATH] [--confirm-live] [--dry-run]"
}

fail() { echo "[backup_offhost] FAIL: $1" >&2; exit 1; }
pass() { echo "[backup_offhost] PASS: $1"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
        --node-yaml) NODE_YAML="${2:-}"; shift 2 ;;
        --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
        --keep) KEEP="${2:-}"; shift 2 ;;
        --passphrase-file) PP_FILE="${2:-}"; shift 2 ;;
        --age-recipient) AGE_RECIPIENT="${2:-}"; shift 2 ;;
        --upload-target) UPLOAD_TARGET="${2:-}"; shift 2 ;;
        --confirm-live) CONFIRM_LIVE=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "[backup_offhost] FATAL: unknown arg '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -n "$DATA_DIR" ]] || { echo "[backup_offhost] FATAL: --data-dir is required" >&2; exit 2; }
[[ -d "$DATA_DIR" ]] || { echo "[backup_offhost] FATAL: data dir missing: $DATA_DIR" >&2; exit 2; }
DATA_DIR="$(realpath "$DATA_DIR")"
[[ -n "$(ls -A "$DATA_DIR")" ]] || { echo "[backup_offhost] FATAL: data dir is empty: $DATA_DIR" >&2; exit 2; }

[[ "$KEEP" =~ ^[0-9]+$ ]] && [[ "$KEEP" -ge 1 ]] || { echo "[backup_offhost] FATAL: --keep must be a positive integer" >&2; exit 2; }

if [[ -z "$NODE_YAML" && -f "$DATA_DIR/../node.yaml" ]]; then
    NODE_YAML="$DATA_DIR/../node.yaml"
fi
if [[ -n "$NODE_YAML" ]]; then
    [[ -f "$NODE_YAML" ]] || { echo "[backup_offhost] FATAL: node yaml missing: $NODE_YAML" >&2; exit 2; }
    NODE_YAML="$(realpath "$NODE_YAML")"
fi

# Out dir: resolve without creating anything in dry-run (read-only plan).
if [[ "$DRY_RUN" -eq 1 ]]; then
    OUT_DIR="$(realpath -m "$OUT_DIR")"
else
    mkdir -p "$OUT_DIR"
    OUT_DIR="$(realpath "$OUT_DIR")"
fi

# Fail closed on layout: out dir must neither contain nor sit inside the live dir.
case "$OUT_DIR" in
    "$DATA_DIR"*) echo "[backup_offhost] FATAL: out dir inside data dir ($OUT_DIR)" >&2; exit 2 ;;
esac
case "$DATA_DIR" in
    "$OUT_DIR"*) echo "[backup_offhost] FATAL: data dir inside out dir ($DATA_DIR)" >&2; exit 2 ;;
esac

# Encryptor selection: age iff requested AND installed, else openssl.
ENCRYPTOR=""
if [[ -n "$AGE_RECIPIENT" ]]; then
    command -v age >/dev/null 2>&1 || { echo "[backup_offhost] FATAL: --age-recipient given but 'age' is not installed; omit it for the openssl path" >&2; exit 2; }
    ENCRYPTOR="age (recipient: $AGE_RECIPIENT)"
    BACKEND="age"
else
    command -v openssl >/dev/null 2>&1 || { echo "[backup_offhost] FATAL: neither age nor openssl available" >&2; exit 2; }
    ENCRYPTOR="openssl enc -aes-256-cbc -pbkdf2 -iter 200000 (fallback; age absent)"
    BACKEND="openssl"
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
IMAGE="$OUT_DIR/backup-$TS"

plan() {
    echo "[backup_offhost] PLAN (dry-run, nothing copied/encrypted/uploaded):"
    echo "  data-dir  : $DATA_DIR"
    echo "  node-yaml : ${NODE_YAML:-<none found, skipped>}"
    echo "  keys      : $DATA_DIR/../keys (inventory of names+modes ONLY, never contents)"
    echo "  out image : $IMAGE/"
    echo "  encryptor : $ENCRYPTOR"
    echo "  1. cp -a data-dir -> $IMAGE/files/ (read-only on live dir)"
    echo "  2. cp node.yaml + write keys.inventory (names+modes only)"
    echo "  3. sha256 manifest over staged files -> $IMAGE/manifest.sha256"
    echo "  4. tar.gz the image, encrypt -> backup-$TS.tar.gz.enc (+ .sha256)"
    if [[ -n "$UPLOAD_TARGET" ]]; then
        echo "  5. upload hook: REFUSED without --confirm-live (currently: $([[ "$CONFIRM_LIVE" -eq 1 ]] && echo 'confirmed' || echo 'NOT confirmed'))"
    else
        echo "  5. upload hook: skipped (no --upload-target; DRY-RUN default, nothing leaves host)"
    fi
    echo "  6. retention: keep newest $KEEP image(s) in $OUT_DIR, prune older backup-* dirs"
    if [[ -d "$OUT_DIR" ]]; then
        echo "  existing images: $(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -type d -name 'backup-*' | wc -l)"
    else
        echo "  existing images: 0 (out dir does not exist yet)"
    fi
}

if [[ "$DRY_RUN" -eq 1 ]]; then plan; exit 0; fi

if [[ "$BACKEND" == "openssl" ]]; then
    [[ -n "$PP_FILE" ]] || { echo "[backup_offhost] FATAL: --passphrase-file is required for the openssl backend" >&2; exit 2; }
    [[ -f "$PP_FILE" ]] || { echo "[backup_offhost] FATAL: passphrase file missing: $PP_FILE" >&2; exit 2; }
    [[ -s "$PP_FILE" ]] || { echo "[backup_offhost] FATAL: passphrase file is empty: $PP_FILE" >&2; exit 2; }
    if [[ -n "$(find "$PP_FILE" -perm /077 2>/dev/null)" ]]; then
        echo "[backup_offhost] WARN: passphrase file is group/other-readable ($PP_FILE); chmod 600 recommended"
    fi
fi

# Refuse the upload early (before doing any work) when confirmation is missing.
if [[ -n "$UPLOAD_TARGET" && "$CONFIRM_LIVE" -ne 1 ]]; then
    echo "[backup_offhost] FATAL: refusing upload to '$UPLOAD_TARGET' without --confirm-live (DRY-RUN default; nothing was copied)" >&2
    exit 2
fi

echo "[backup_offhost] data-dir : $DATA_DIR"
echo "[backup_offhost] image    : $IMAGE"
echo "[backup_offhost] encryptor: $ENCRYPTOR"

# 1. Stage: copy only. Never move, never write into the live dir.
mkdir -p "$IMAGE/files"
cp -a "$DATA_DIR/." "$IMAGE/files/"
echo "[backup_offhost] step 1/6 data staged (read-only copy, $(du -sh "$IMAGE/files" | cut -f1))"

# 2. node.yaml copy + keys inventory (names + modes ONLY — never key contents).
if [[ -n "$NODE_YAML" ]]; then
    cp -p "$NODE_YAML" "$IMAGE/node.yaml"
    echo "[backup_offhost] step 2/6 node.yaml staged"
else
    echo "[backup_offhost] step 2/6 no node.yaml found, skipped"
fi
KEYS_DIR="$DATA_DIR/../keys"
if [[ -d "$KEYS_DIR" ]]; then
    ( cd "$KEYS_DIR" && find . -mindepth 1 -maxdepth 1 -printf '%M %u %g %p\n' | LC_ALL=C sort ) > "$IMAGE/keys.inventory"
    echo "[backup_offhost] keys inventory staged ($(wc -l < "$IMAGE/keys.inventory") entries, names+modes only)"
else
    echo "# no keys dir adjacent to data dir ($KEYS_DIR); inventory empty" > "$IMAGE/keys.inventory"
    echo "[backup_offhost] WARN: no adjacent keys dir; empty inventory staged"
fi

# 3. Manifest over the staged image (written via temp + mv: never self-hashes).
MANIFEST_TMP="$IMAGE/manifest.sha256.tmp"
( cd "$IMAGE" && find files -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "$MANIFEST_TMP" )
( cd "$IMAGE" && sha256sum keys.inventory >> "$MANIFEST_TMP" )
if [[ -f "$IMAGE/node.yaml" ]]; then
    ( cd "$IMAGE" && sha256sum node.yaml >> "$MANIFEST_TMP" )
fi
mv "$MANIFEST_TMP" "$IMAGE/manifest.sha256"
NFILES="$(wc -l < "$IMAGE/manifest.sha256")"
[[ "$NFILES" -gt 0 ]] || fail "manifest empty — staged image has no files"
echo "[backup_offhost] step 3/6 manifest written ($NFILES entries)"

# 4. Tar + encrypt. The tarball is built outside the image, encrypted, and
#    only the .enc artifact (+ its sha256) is kept next to the plaintext stage.
TARGZ_TMP="$OUT_DIR/.backup-$TS.tar.gz.tmp"
tar -czf "$TARGZ_TMP" -C "$IMAGE" files keys.inventory manifest.sha256 ${NODE_YAML:+node.yaml}
ENC="$IMAGE/backup-$TS.tar.gz.enc"
if [[ "$BACKEND" == "age" ]]; then
    age -r "$AGE_RECIPIENT" -o "$ENC" "$TARGZ_TMP"
else
    openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -in "$TARGZ_TMP" -out "$ENC" -pass "file:$PP_FILE"
fi
rm -f "$TARGZ_TMP"
( cd "$IMAGE" && sha256sum "backup-$TS.tar.gz.enc" > "backup-$TS.tar.gz.enc.sha256" )
echo "[backup_offhost] step 4/6 encrypted image ready ($(du -h "$ENC" | cut -f1))"

# 5. Upload hook. Local directory targets only, and only with --confirm-live
#    (checked up front). Remote/URI targets are always refused: fail closed.
if [[ -z "$UPLOAD_TARGET" ]]; then
    echo "[backup_offhost] step 5/6 upload skipped (no --upload-target; artifact stays at $ENC)"
else
    case "$UPLOAD_TARGET" in
        *://*|*:*)
            fail "remote upload target refused (no uploader configured): $UPLOAD_TARGET — copy $ENC manually"
            ;;
    esac
    mkdir -p "$UPLOAD_TARGET"
    UPLOAD_ABS="$(realpath "$UPLOAD_TARGET")"
    case "$UPLOAD_ABS" in
        "$DATA_DIR"*) fail "upload target inside live data dir ($UPLOAD_ABS)" ;;
    esac
    case "$DATA_DIR" in
        "$UPLOAD_ABS"*) fail "live data dir inside upload target ($DATA_DIR)" ;;
    esac
    if command -v rsync >/dev/null 2>&1; then
        rsync -a -- "$ENC" "$ENC.sha256" "$UPLOAD_ABS/"
    else
        cp -p -- "$ENC" "$ENC.sha256" "$UPLOAD_ABS/"
    fi
    echo "[backup_offhost] step 5/6 uploaded (local copy) to $UPLOAD_ABS"
fi

# 6. Retention: keep newest KEEP image dirs, prune older backup-* dirs only.
mapfile -t EXISTING < <(find "$OUT_DIR" -mindepth 1 -maxdepth 1 -type d -name 'backup-*' | LC_ALL=C sort)
if (( ${#EXISTING[@]} > KEEP )); then
    NDEL=$((${#EXISTING[@]} - KEEP))
    for (( i = 0; i < NDEL; i++ )); do
        victim="${EXISTING[$i]}"
        case "$victim" in
            "$OUT_DIR"/backup-*) rm -rf "$victim"; echo "[backup_offhost] pruned old image: $victim" ;;
            *) fail "refusing to prune unexpected path: $victim" ;;
        esac
    done
    echo "[backup_offhost] step 6/6 retention: pruned $NDEL, kept $KEEP"
else
    echo "[backup_offhost] step 6/6 retention: ${#EXISTING[@]} image(s) present, keep=$KEEP, nothing pruned"
fi

pass "off-host image complete: $IMAGE (manifest $NFILES entries, encrypted, live dir untouched)"
