#!/usr/bin/env bash
# Deploy the VitePress documentation site and its nginx server block to nodeA.
#
# Usage: scripts/deploy-docs-site.sh [--build-only] [--no-cert] [--no-reload]
#
#   --build-only  build docs-site locally, do not touch the server
#   --no-cert     skip certbot (the certificate already covers docs.stellereum.org)
#   --no-reload   install files but do not reload nginx
#
# Override the target with DOCS_REMOTE=user@host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE="${DOCS_REMOTE:-root@212.113.103.105}"
DOMAIN="docs.stellereum.org"
DOCS_DIR="$ROOT/docs-site"
DIST_DIR="$DOCS_DIR/.vitepress/dist"
NGINX_CONF="$ROOT/deploy/nginx/docs.stellereum.org.conf"
REMOTE_ROOT="/var/www/$DOMAIN"
REMOTE_CONF="/etc/nginx/sites-available/stellereum-docs"
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=15 "$REMOTE")
SCP=(scp -o BatchMode=yes -o ConnectTimeout=15)

BUILD_ONLY=0
NO_CERT=0
NO_RELOAD=0

usage() {
  sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

die() { echo "error: $*" >&2; exit 1; }
log() { echo "==> $*"; }

while (($#)); do
  case "$1" in
    --build-only) BUILD_ONLY=1 ;;
    --no-cert)    NO_CERT=1 ;;
    --no-reload)  NO_RELOAD=1 ;;
    -h|--help)    usage; exit 0 ;;
    *) die "unknown flag: $1 (try --help)" ;;
  esac
  shift
done

[[ -f "$NGINX_CONF" ]] || die "missing nginx config: $NGINX_CONF"
[[ -d "$DOCS_DIR" ]] || die "missing docs-site/ — the docs build has not landed yet"

# ---------------------------------------------------------------- build
log "building $DOMAIN from $DOCS_DIR"
cd "$DOCS_DIR"
if [[ -f package-lock.json ]]; then
  npm ci || npm install
else
  npm install
fi
npm run build
[[ -f "$DIST_DIR/index.html" ]] || die "build produced no $DIST_DIR/index.html"

if ((BUILD_ONLY)); then
  log "build complete: $DIST_DIR (server untouched)"
  exit 0
fi

# ---------------------------------------------------------------- upload
log "creating $REMOTE_ROOT on $REMOTE"
"${SSH[@]}" "install -d -o www-data -g www-data -m 0755 '$REMOTE_ROOT'"

log "syncing $DIST_DIR/ -> $REMOTE:$REMOTE_ROOT/"
if command -v rsync >/dev/null 2>&1 && "${SSH[@]}" "command -v rsync >/dev/null 2>&1"; then
  rsync -az --delete --chown=www-data:www-data \
    -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
    "$DIST_DIR/" "$REMOTE:$REMOTE_ROOT/"
else
  # This environment may lack rsync on either side. tar preserves the same
  # result: clear the target, stream the build, restore www-data ownership.
  log "rsync not available; using tar over ssh"
  "${SSH[@]}" "find '$REMOTE_ROOT' -mindepth 1 -delete"
  tar -C "$DIST_DIR" -cf - . | "${SSH[@]}" "tar -C '$REMOTE_ROOT' -xf - && chown -R www-data:www-data '$REMOTE_ROOT'"
fi

# ---------------------------------------------------------- nginx config
log "installing nginx block $REMOTE_CONF"
remote_tmp="$("${SSH[@]}" "mktemp /tmp/stellereum-docs.XXXXXX.conf")"
[[ -n "$remote_tmp" ]] || die "failed to create remote temp file"
q_remote_tmp="$(printf '%q' "$remote_tmp")"
"${SCP[@]}" "$NGINX_CONF" "$REMOTE:$remote_tmp"
"${SSH[@]}" "
  set -e
  trap 'rm -f $q_remote_tmp' EXIT
  if [ -f '$REMOTE_CONF' ]; then
    cp -a '$REMOTE_CONF' '$REMOTE_CONF.bak.\$(date +%Y%m%d%H%M%S)'
  fi
  install -m 0644 $q_remote_tmp '$REMOTE_CONF'
  ln -sfn '$REMOTE_CONF' /etc/nginx/sites-enabled/stellereum-docs
  nginx -t
"

if ((NO_RELOAD)); then
  log "--no-reload: nginx config tested, not reloaded"
else
  log "reloading nginx"
  "${SSH[@]}" "systemctl reload nginx"
fi

# --------------------------------------------------------------- certbot
if ((NO_CERT)); then
  log "--no-cert: skipping certbot"
else
  if "${SSH[@]}" "openssl x509 -in /etc/letsencrypt/live/stellereum/fullchain.pem -noout -text | grep -q 'DNS:$DOMAIN'"; then
    log "certificate already covers $DOMAIN"
  else
    log "extending the stellereum certificate with $DOMAIN"
    "${SSH[@]}" "certbot --nginx -d '$DOMAIN' --non-interactive --agree-tos --expand"
    "${SSH[@]}" "nginx -t"
    if ((NO_RELOAD)); then
      log "--no-reload: certbot issued, nginx not reloaded by this script"
    else
      "${SSH[@]}" "systemctl reload nginx"
    fi
  fi
fi

# --------------------------------------------------------------- verify
log "verifying https://$DOMAIN/"
code="$(curl -fsS -o /dev/null -w '%{http_code}' "https://$DOMAIN/" || true)"
[[ "$code" == "200" ]] || die "expected HTTP 200 from https://$DOMAIN/, got '${code:-none}'"
echo "200"
# sed drains the body so curl never sees EPIPE (which pipefail would report).
curl -fsS "https://$DOMAIN/" | sed -n '1,20p'

log "docs deployed: https://$DOMAIN/"
