#!/usr/bin/env bash
# ==============================================================================
# verify-cosign-artifact.sh — Verify a release/snapshot artifact with cosign
# (and optional .sha256 digest) using the OIDC workflow identity documented in
# docs/RELEASE.md.
#
# Usage:
#   scripts/verify-cosign-artifact.sh [OPTIONS] <artifact>
#
# Options:
#   --require                Fail closed if cosign, <artifact>.sig, or
#                            <artifact>.pem is missing, or verification fails
#   --if-present             Verify if <artifact>.sig and <artifact>.pem exist;
#                            skip with a clear notice if absent (default)
#   --sig PATH               Override signature path (default: <artifact>.sig)
#   --pem PATH               Override certificate path (default: <artifact>.pem)
#   --sha256 PATH            Override SHA-256 file (default: <artifact>.sha256 if present)
#   --identity-regexp REGEX  Override --certificate-identity-regexp
#                            (default: ^https://github\.com/stellereum/stellereum/)
#   --oidc-issuer URL        Override --certificate-oidc-issuer
#                            (default: https://token.actions.githubusercontent.com)
#   -h, --help               Show this help
#
# Exit codes:
#   0  verified (or cleanly skipped under --if-present)
#   1  verification failed or missing required material
#   64 usage error
# ==============================================================================
set -euo pipefail

MODE="if-present"
SIG_FILE=""
PEM_FILE=""
SHA256_FILE=""
SHA256_EXPLICIT=0
IDENTITY_REGEXP="${COSIGN_CERT_IDENTITY_REGEXP:-^https://github\\.com/stellereum/stellereum/}"
OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
ARTIFACT=""

note() { printf '[verify-cosign] %s\n' "$*"; }
warn() { printf '[verify-cosign] WARN: %s\n' "$*" >&2; }
err()  { printf '[verify-cosign] ERROR: %s\n' "$*" >&2; }
usage() { sed -n '2,/^# ====/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --require) MODE="require"; shift ;;
        --if-present) MODE="if-present"; shift ;;
        --sig) [ $# -ge 2 ] || { err "--sig requires a path"; exit 64; }; SIG_FILE="$2"; shift 2 ;;
        --sig=*) SIG_FILE="${1#*=}"; shift ;;
        --pem) [ $# -ge 2 ] || { err "--pem requires a path"; exit 64; }; PEM_FILE="$2"; shift 2 ;;
        --pem=*) PEM_FILE="${1#*=}"; shift ;;
        --sha256) [ $# -ge 2 ] || { err "--sha256 requires a path"; exit 64; }; SHA256_FILE="$2"; SHA256_EXPLICIT=1; shift 2 ;;
        --sha256=*) SHA256_FILE="${1#*=}"; SHA256_EXPLICIT=1; shift ;;
        --identity-regexp) [ $# -ge 2 ] || { err "--identity-regexp requires a value"; exit 64; }; IDENTITY_REGEXP="$2"; shift 2 ;;
        --identity-regexp=*) IDENTITY_REGEXP="${1#*=}"; shift ;;
        --oidc-issuer) [ $# -ge 2 ] || { err "--oidc-issuer requires a URL"; exit 64; }; OIDC_ISSUER="$2"; shift 2 ;;
        --oidc-issuer=*) OIDC_ISSUER="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        --)
            shift
            while [ $# -gt 0 ]; do
                if [ -n "$ARTIFACT" ]; then
                    err "unexpected extra argument: $1"
                    exit 64
                fi
                ARTIFACT="$1"
                shift
            done
            ;;
        -*) err "unknown flag: $1"; usage >&2; exit 64 ;;
        *)
            if [ -n "$ARTIFACT" ]; then
                err "unexpected extra argument: $1"
                exit 64
            fi
            ARTIFACT="$1"
            shift
            ;;
    esac
done

if [ -z "$ARTIFACT" ]; then
    err "missing <artifact> argument"
    usage >&2
    exit 64
fi

if [ ! -f "$ARTIFACT" ] || [ ! -r "$ARTIFACT" ]; then
    err "artifact not found or unreadable: $ARTIFACT"
    exit 1
fi

if [ -z "$SIG_FILE" ]; then
    SIG_FILE="${ARTIFACT}.sig"
fi
if [ -z "$PEM_FILE" ]; then
    PEM_FILE="${ARTIFACT}.pem"
fi
if [ "$SHA256_EXPLICIT" -eq 0 ]; then
    SHA256_FILE="${ARTIFACT}.sha256"
fi

if [ "$SHA256_EXPLICIT" -eq 1 ] && { [ ! -f "$SHA256_FILE" ] || [ ! -r "$SHA256_FILE" ]; }; then
    err "specified SHA-256 file not found or unreadable: $SHA256_FILE"
    exit 1
fi

if [ -f "$SHA256_FILE" ]; then
    [ -r "$SHA256_FILE" ] || { err "SHA-256 file not readable: $SHA256_FILE"; exit 1; }
    command -v sha256sum >/dev/null 2>&1 || { err "sha256sum not found in PATH"; exit 1; }

    expected_sha="$(awk 'NF>=1 {print tolower($1); exit}' "$SHA256_FILE")"
    if ! [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
        err "invalid SHA-256 format in $SHA256_FILE"
        exit 1
    fi
    actual_sha="$(sha256sum "$ARTIFACT" | awk '{print tolower($1)}')"
    if [ "$actual_sha" != "$expected_sha" ]; then
        err "SHA-256 mismatch for $ARTIFACT: expected=$expected_sha actual=$actual_sha"
        exit 1
    fi
    note "OK: SHA-256 verified ($actual_sha) against $SHA256_FILE"
fi

has_sig=0
has_pem=0
[ -f "$SIG_FILE" ] && has_sig=1
[ -f "$PEM_FILE" ] && has_pem=1

if [ "$MODE" = "require" ]; then
    if ! command -v cosign >/dev/null 2>&1; then
        err "cosign not found in PATH (--require is set)"
        exit 1
    fi
    if [ "$has_sig" -eq 0 ] || [ ! -r "$SIG_FILE" ]; then
        err "cosign signature not found or unreadable: $SIG_FILE (--require is set)"
        exit 1
    fi
    if [ "$has_pem" -eq 0 ] || [ ! -r "$PEM_FILE" ]; then
        err "cosign certificate not found or unreadable: $PEM_FILE (--require is set)"
        exit 1
    fi
else
    if [ "$has_sig" -eq 0 ] && [ "$has_pem" -eq 0 ]; then
        note "SKIP: no cosign signature/certificate found ($SIG_FILE, $PEM_FILE); skipping verification (--if-present)"
        exit 0
    fi
    if [ "$has_sig" -ne "$has_pem" ]; then
        err "incomplete cosign bundle for $ARTIFACT: sig($SIG_FILE)=$has_sig pem($PEM_FILE)=$has_pem"
        exit 1
    fi
    [ -r "$SIG_FILE" ] || { err "cosign signature unreadable: $SIG_FILE"; exit 1; }
    [ -r "$PEM_FILE" ] || { err "cosign certificate unreadable: $PEM_FILE"; exit 1; }
    if ! command -v cosign >/dev/null 2>&1; then
        warn "cosign signature/certificate present for $ARTIFACT, but 'cosign' is not installed in PATH; skipping verification (--if-present; pass --require to fail closed)"
        exit 0
    fi
fi

note "verifying $ARTIFACT with cosign verify-blob (issuer=$OIDC_ISSUER, identity=$IDENTITY_REGEXP)"
if ! cosign verify-blob \
    --certificate "$PEM_FILE" \
    --signature "$SIG_FILE" \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$ARTIFACT"; then
    err "cosign verify-blob FAILED for $ARTIFACT"
    exit 1
fi

note "OK: cosign signature verified for $ARTIFACT"
