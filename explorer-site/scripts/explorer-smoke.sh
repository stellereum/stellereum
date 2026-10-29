#!/usr/bin/env bash
# Explorer smoke test — fails loudly on blank/error responses.
#
# Usage: scripts/explorer-smoke.sh [BASE_URL]
#   default BASE_URL: https://explorer.stellereum.org
#
# Checks:
#   1. Pages `/`, `/blocks`, `/txs`, `/validators` answer HTTP 200 and contain
#      the `<div id="root">` mount point.
#   2. Every `/assets/*` file referenced by the served `index.html` resolves
#      HTTP 200 (catches stale-index.html / hashed-asset mismatch deploys).
#   3. The indexer envelopes the UI depends on still hold:
#      `/blocks` -> `{blocks: [...]}`, `/txs` -> `{transactions: [...]}`.
#   4. When a headless chromium is available, each page is actually rendered
#      and must leave a non-empty `#root` with no uncaught JS errors
#      (catches the `*.map is not a function` blank-page class).
set -u
BASE="${1:-https://explorer.stellereum.org}"
FAIL=0

fail() { echo "SMOKE-FAIL: $*"; FAIL=1; }
pass() { echo "SMOKE-OK:   $*"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "SMOKE-FAIL: missing tool: $1"; exit 2; }; }
need curl; need python3

check_page() {
  local path="$1" code body
  body="$(curl -sk --max-time 20 -w '\n%{http_code}' "$BASE$path")"
  code="$(printf '%s' "$body" | tail -1)"
  body="$(printf '%s' "$body" | head -n -1)"
  if [ "$code" != "200" ]; then fail "GET $path -> HTTP $code"; return; fi
  if ! printf '%s' "$body" | grep -q '<div id="root">'; then
    fail "GET $path -> 200 but no <div id=\"root\"> mount point"; return
  fi
  pass "GET $path -> 200 + mount point"
}

check_page "/" ; check_page "/blocks" ; check_page "/txs" ; check_page "/validators"

# Stale-asset check: every script/link the served index.html points at must exist.
INDEX="$(curl -sk --max-time 20 "$BASE/")"
ASSETS="$(printf '%s' "$INDEX" | grep -oE '/assets/[^"'\''<> ]+' | sort -u)"
if [ -z "$ASSETS" ]; then
  fail "index.html references no /assets/* files"
else
  for a in $ASSETS; do
    code="$(curl -sk --max-time 20 -o /dev/null -w '%{http_code}' "$BASE$a")"
    if [ "$code" != "200" ]; then fail "asset $a -> HTTP $code (stale index.html?)"
    else pass "asset $a -> 200"; fi
  done
fi

# Indexer envelope contract (the UI unwraps these; a shape change = blank page).
python3 - "$BASE" <<'EOF'
import json, sys, urllib.request
base = sys.argv[1]
def get(path):
    with urllib.request.urlopen(base + path, timeout=20) as r:
        return r.status, r.read().decode()
ok = True
for path, key in [("/api/v2/stats", "tip_height"),
                  ("/api/v2/blocks?limit=1", "blocks"),
                  ("/api/v2/txs?limit=1", "transactions"),
                  ("/api/v2/validators", "validators")]:
    try:
        status, body = get(path)
        data = json.loads(body)
        if status != 200 or key not in data:
            print(f"SMOKE-FAIL: GET {path} -> status {status}, missing key '{key}'"); ok = False
        elif key != "tip_height" and not isinstance(data[key], list):
            print(f"SMOKE-FAIL: GET {path} -> '{key}' is not a list: {str(data[key])[:80]}"); ok = False
        else:
            print(f"SMOKE-OK:   GET {path} -> 200, key '{key}' present")
    except Exception as e:
        print(f"SMOKE-FAIL: GET {path} -> {e}"); ok = False
sys.exit(0 if ok else 1)
EOF
[ $? -ne 0 ] && FAIL=1

# Headless render check (only when chromium exists).
CHROME="$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)"
if [ -z "$CHROME" ]; then
  echo "SMOKE-SKIP: no headless chromium found, skipping render check"
else
  for path in "/" "/blocks" "/validators"; do
    dom_file="$(mktemp)"; log_file="$(mktemp)"
    timeout 90 "$CHROME" --headless=new --disable-gpu --no-sandbox \
      --enable-logging=stderr --log-level=0 --virtual-time-budget=15000 \
      --dump-dom "$BASE$path" >"$dom_file" 2>"$log_file" || fail "render $path -> chromium exit $?"
    if grep -qE "Uncaught|TypeError: .* is not a function" "$log_file"; then
      fail "render $path -> uncaught JS error: $(grep -oE 'Uncaught[^"]*|TypeError[^"]*' "$log_file" | head -1)"
    fi
    root_len="$(python3 -c "
import re,sys
dom = open('$dom_file').read()
m = re.search(r'<div id=\"root\">(.*)</div>\s*</body>', dom, re.S)
print(len(m.group(1)) if m else 0)
")"
    if [ "${root_len:-0}" -lt 500 ]; then
      fail "render $path -> BLANK page (#root inner length ${root_len:-0})"
    else
      pass "render $path -> non-blank (#root inner length $root_len)"
    fi
    rm -f "$dom_file" "$log_file"
  done
fi

if [ "$FAIL" -ne 0 ]; then echo "SMOKE RESULT: FAIL"; exit 1; fi
echo "SMOKE RESULT: PASS"
