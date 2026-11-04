#!/usr/bin/env bash
# add-peer.sh — network side of onboarding: admit one peer stanza.
#
# Takes the peer-stanza block produced by scripts/join-network.sh (or by
# `stellereum keys peer-stanza`) and:
#   1. appends the peer entry to node.yaml `peers:` (idempotent: a node-id
#      already present is left untouched)
#   2. appends the ed-pub:falcon-pub mapping to STELL_PEER_PQ_KEYS in the env
#      file (idempotent, comma-separated, like the ed-pub entries in node.yaml)
#   3. rolling-restarts ONE systemd unit (default: restart only, never wipe)
#
# Backups of both files are taken before any edit (timestamped .bak.*).
#
# Roles:
#   --role observer (default): peers: entry ONLY. This does NOT change the
#      validator set (discovery-guard tests pin this invariant), so it does
#      not change the genesis root and a rolling restart is safe.
#   --role validator: peers: entry PLUS the id in `validators:`. This CHANGES
#      the validator set and therefore the genesis state root: EVERY node must
#      get the same edit, and every data directory must be wiped before the
#      next start (the fingerprint guard refuses old data). That is a
#      COORDINATED chain restart, not a rolling one — the script says so and
#      refuses --restart unless --i-understand-genesis-changes is also given.
#
# Usage:
#   scripts/add-peer.sh --node-yaml PATH --env-file PATH [options] [STANZA_FILE]
#   ... | scripts/add-peer.sh --node-yaml PATH --env-file PATH [options]
#
# Options:
#   --node-yaml PATH   node.yaml to edit (required)
#   --env-file PATH    env file holding STELL_PEER_PQ_KEYS (required)
#   --role R           observer|validator (default: observer)
#   --unit NAME        systemd unit to restart (default: none — print the
#                      restart command instead; pass --unit stell-nodeA etc.)
#   --restart          rolling-restart the unit after the edit (observers only,
#                      or validators with --i-understand-genesis-changes)
#   --no-restart       never restart (default when --unit is absent)
#   --i-understand-genesis-changes
#                      acknowledge the coordinated-restart requirement for
#                      --role validator
#   --i-understand-fragile-quorum
#                      acknowledge a FRAGILE quorum outcome for --role validator
#                      (quorum needs 100% of the set — notably N=3, which needs
#                      3/3 — so any single halt stops the chain). The script
#                      precomputes quorum before/after and refuses a fragile
#                      outcome without this flag. Fail-open with a loud gate:
#                      the chain still starts, but never silently.
#   -h|--help
#
# Exit codes: 0 ok (peer present afterwards), 1 error, 2 usage.
set -uo pipefail

NODE_YAML=""
ENV_FILE=""
ROLE="observer"
UNIT=""
RESTART=0
UNDERSTAND=0
UNDERSTAND_FRAGILE=0
STANZA_FILE=""

usage() {
  sed -n '2,/^set -uo/p' "$0" | sed 's/^# \{0,1\}//'
}

die() { printf 'add-peer.sh: ERROR: %s\n' "$*" >&2; exit 1; }
warn() { printf 'add-peer.sh: WARN: %s\n' "$*" >&2; }
note() { printf 'add-peer.sh: %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --node-yaml) NODE_YAML="${2:?--node-yaml needs a path}"; shift 2 ;;
    --env-file) ENV_FILE="${2:?--env-file needs a path}"; shift 2 ;;
    --role) ROLE="${2:?--role needs observer|validator}"; shift 2 ;;
    --unit) UNIT="${2:?--unit needs a unit name}"; shift 2 ;;
    --restart) RESTART=1; shift ;;
    --no-restart) RESTART=0; shift ;;
    --i-understand-genesis-changes) UNDERSTAND=1; shift ;;
    --i-understand-fragile-quorum) UNDERSTAND_FRAGILE=1; shift ;;
    -h|--help) usage; exit 2 ;;
    -*) printf 'add-peer.sh: unknown argument %s (see --help)\n' "$1" >&2; exit 2 ;;
    *) [ -z "$STANZA_FILE" ] || die "only one stanza file argument";
       STANZA_FILE="$1"; shift ;;
  esac
done

[ -n "$NODE_YAML" ] || { usage >&2; die "missing --node-yaml"; }
[ -n "$ENV_FILE" ] || { usage >&2; die "missing --env-file"; }
[ -f "$NODE_YAML" ] || die "$NODE_YAML not found";
[ -f "$ENV_FILE" ] || die "$ENV_FILE not found";
case "$ROLE" in observer|validator) ;; *) die "--role must be observer|validator" ;; esac
if [ "$ROLE" = validator ] && [ "$RESTART" = 1 ] && [ "$UNDERSTAND" = 0 ]; then
  die "--role validator changes the genesis root: re-run with --i-understand-genesis-changes (and coordinate every node + wipe, see docs/OPERATIONS.md §10)"
fi

# --- 0. read the stanza (file or stdin) ----------------------------------------
if [ -n "$STANZA_FILE" ]; then
  [ -f "$STANZA_FILE" ] || die "stanza file $STANZA_FILE not found"
  STANZA="$(cat "$STANZA_FILE")"
elif [ -t 0 ]; then
  usage >&2; die "no stanza given (pass a file or pipe one on stdin)"
else
  STANZA="$(cat)"
fi
[ -n "$STANZA" ] || die "empty stanza"

# --- 1. parse + validate --------------------------------------------------------
peer_name="$(printf '%s' "$STANZA" | grep -m1 -E '^[[:space:]]*-[[:space:]]*name:' | sed -E 's/.*name:[[:space:]]*//; s/^"//; s/"$//' || true)"
node_id="$(printf '%s' "$STANZA" | grep -m1 -E 'node-id:' | grep -oE 'inf1:[0-9a-fA-F]+' || true)"
ed_pub="$(printf '%s' "$STANZA" | grep -m1 -E 'ed-pub:' | grep -oE '[0-9a-fA-F]{64}' || true)"
x_pub="$(printf '%s' "$STANZA" | grep -m1 -E 'x-pub:' | grep -oE '[0-9a-fA-F]{64}' || true)"
endpoint="$(printf '%s' "$STANZA" | grep -m1 -E 'endpoints:' | grep -oE '[A-Za-z0-9._-]+:[0-9]+' || true)"
# PQ mapping line: "# <ed64>:<falcon-hex>" (falcon-512 pub = 897 bytes = 1794 hex).
pq_line="$(printf '%s' "$STANZA" | grep -m1 -E '^#[[:space:]]*[0-9a-fA-F]{64}:[0-9a-fA-F]+' | sed -E 's/^#[[:space:]]*//' || true)"
falcon_pub="${pq_line#*:}"

[ -n "$node_id" ] || die "stanza has no node-id (expected inf1:<40 hex>)"
id_hex="${node_id#inf1:}"
[ "${#id_hex}" = 40 ] || die "node-id must carry 40 hex chars, got ${#id_hex}"
case "$id_hex$ed_pub$x_pub" in *[!0-9a-fA-F]*|"") die "node-id/ed-pub/x-pub must be hex" ;; esac
[ "${#ed_pub}" = 64 ] || die "ed-pub must be 64 hex chars, got ${#ed_pub}"
[ "${#x_pub}" = 64 ] || die "x-pub must be 64 hex chars, got ${#x_pub}"
[ -n "$endpoint" ] || { endpoint="REPLACE_WITH_PUBLIC_IP:9410"; warn "stanza has no endpoints; using placeholder $endpoint (fix it)"; }
[ -z "$peer_name" ] && peer_name="peer-${id_hex:0:8}"
if [ -n "$pq_line" ]; then
  pq_ed="${pq_line%%:*}"
  [ "$pq_ed" = "$ed_pub" ] || die "PQ mapping ed ($pq_ed) does not match ed-pub ($ed_pub)"
  case "$falcon_pub" in ""|*[!0-9a-fA-F]*) die "PQ mapping falcon-pub must be hex" ;; esac
  [ "${#falcon_pub}" = 1794 ] || warn "falcon-pub is ${#falcon_pub} hex chars, expected 1794 (Falcon-512); continuing anyway"
else
  warn "stanza has no PQ mapping line; STELL_PEER_PQ_KEYS will not be updated"
fi
note "peer: name=$peer_name id=$node_id endpoint=$endpoint"

TS="$(date -u +%Y%m%dT%H%M%SZ)"

# --- 1b. quorum-safety precompute + gate (role=validator only) ----------------
# Runs BEFORE any file is mutated, so a refused fragile outcome leaves both
# files untouched (backups are only taken on actual edits below).
#
# Config validator sets carry power 1 each, so quorum = floor(2N/3)+1 and the
# outcome is fragile exactly when a single halt breaks it (N-1 < quorum, i.e.
# N<=3) — notably N=3, which needs 3/3 (урок ночи C). On-chain stake weights
# can only make this WORSE (unequal power concentrates fault in the big
# holders), never better, so the equal-power math is the optimistic bound. A
# fragile outcome needs --i-understand-fragile-quorum, otherwise the script
# refuses (fail-open with a loud gate: the chain still starts, but never
# silently).
validators_count() {
  awk '/^validators:/{invs=1; next} /^[^[:space:]#]/{invs=0} invs' "$NODE_YAML" \
    | grep -cE 'inf1:[0-9a-fA-F]{40}' || true
}
quorum_of() { printf '%s' "$(( ($1 * 2) / 3 + 1 ))"; }
if [ "$ROLE" = validator ]; then
  # Check the validators: block specifically (the id also appears in peers:).
  if awk '/^validators:/{invs=1; next} /^[^[:space:]#]/{invs=0} invs' "$NODE_YAML" | grep -qF "$node_id"; then
    N_NOW="$(validators_count)"
    Q_NOW="$(quorum_of "$N_NOW")"
    note "quorum-safety: $N_NOW validator(s), quorum $Q_NOW (unchanged — $node_id already listed)"
    if [ "$N_NOW" -gt 0 ] && [ $(( N_NOW - 1 )) -lt "$Q_NOW" ]; then
      warn "QUORUM-SAFETY: current set is FRAGILE — quorum $Q_NOW of $N_NOW requires 100% of the set; any single halt stops the chain"
    fi
  else
    grep -qE '^[[:space:]]*validators:' "$NODE_YAML" || die "$NODE_YAML has no validators: block"
    N_BEFORE="$(validators_count)"
    N_AFTER=$(( N_BEFORE + 1 ))
    Q_BEFORE="$(quorum_of "$N_BEFORE")"
    Q_AFTER="$(quorum_of "$N_AFTER")"
    note "quorum-safety: $N_BEFORE validator(s) (quorum $Q_BEFORE) -> $N_AFTER validator(s) (quorum $Q_AFTER)"
    if [ "$N_AFTER" -eq 3 ]; then
      warn "QUORUM-SAFETY: N=3 equal-power set needs 3/3 for quorum — any single halt stops the chain (урок ночи C)"
    fi
    if [ $(( N_AFTER - 1 )) -lt "$Q_AFTER" ]; then
      warn "QUORUM-SAFETY: resulting set is FRAGILE — quorum $Q_AFTER of $N_AFTER requires 100% of the set; any single halt stops the chain."
      if [ "$UNDERSTAND_FRAGILE" = 0 ]; then
        die "fragile quorum outcome: re-run with --i-understand-fragile-quorum to confirm you accept that any single validator halt stops the chain"
      fi
      note "fragile-quorum outcome explicitly acknowledged (--i-understand-fragile-quorum)"
    fi
  fi
fi

# --- 2. node.yaml: append peer (idempotent) -------------------------------------
# Check INSIDE the peers: block specifically (the id legitimately also appears
# in validators: — a file-global grep would skip a missing peers entry and
# silently leave an asymmetric config behind).
if awk '/^peers:/{inps=1; next} /^[^[:space:]#]/{inps=0} inps' "$NODE_YAML" | grep -qF "$node_id"; then
  note "$NODE_YAML already has a peers: entry for $node_id; peer entry unchanged"
else
  cp "$NODE_YAML" "$NODE_YAML.bak.$TS"
  if grep -qE '^[[:space:]]*peers:[[:space:]]*\[\]' "$NODE_YAML"; then
    # Empty `peers: []` -> expand to a list with this entry.
    python3 - "$NODE_YAML" "$peer_name" "$node_id" "$ed_pub" "$x_pub" "$endpoint" <<'EOF' || die "failed to edit $NODE_YAML"
import sys
path, name, nid, ed, x, ep = sys.argv[1:7]
entry = (f'peers:\n'
         f'  - name: {name}\n'
         f'    node-id: "{nid}"\n'
         f'    ed-pub: "{ed}"\n'
         f'    x-pub: "{x}"\n'
         f'    endpoints: ["{ep}"]\n'
         f'    allow: ["*"]\n')
src = open(path).read()
import re
new, n = re.subn(r'(?m)^peers:\s*\[\]\s*$', entry.rstrip('\n'), src, count=1)
assert n == 1, "peers: [] anchor not found"
open(path, 'w').write(new)
EOF
  else
    # Insert at the END of the existing `peers:` block (the run of indented
    # lines after the `peers:` header) — never at EOF, which may be the
    # `validators:` block. Entries use the templates' indent (two spaces).
    grep -qE '^[[:space:]]*peers:' "$NODE_YAML" || die "$NODE_YAML has no peers: block"
    python3 - "$NODE_YAML" "$peer_name" "$node_id" "$ed_pub" "$x_pub" "$endpoint" <<'EOF' || die "failed to edit $NODE_YAML"
import sys
path, name, nid, ed, x, ep = sys.argv[1:7]
entry = (f'  - name: {name}\n'
         f'    node-id: "{nid}"\n'
         f'    ed-pub: "{ed}"\n'
         f'    x-pub: "{x}"\n'
         f'    endpoints: ["{ep}"]\n'
         f'    allow: ["*"]\n')
lines = open(path).read().splitlines(keepends=True)
start = next(i for i, ln in enumerate(lines) if ln.lstrip().startswith('peers:') and not ln.startswith((' ', '\t')))
end = start + 1
while end < len(lines) and (lines[end].startswith((' ', '\t')) or lines[end].strip() == ''):
    end += 1
lines.insert(end, entry)
open(path, 'w').write(''.join(lines))
EOF
  fi
  note "appended $peer_name ($node_id) to $NODE_YAML (backup $NODE_YAML.bak.$TS)"
fi

# --- 3. validators: (role=validator only; genesis-changing) --------------------
# Quorum-safety was precomputed and gated in §1b before any mutation; here is
# only the edit itself.
if [ "$ROLE" = validator ]; then
  # Check the validators: block specifically (the id also appears in peers:).
  if awk '/^validators:/{invs=1; next} /^[^[:space:]#]/{invs=0} invs' "$NODE_YAML" | grep -qF "$node_id"; then
    note "$node_id already in validators:; unchanged"
  else
    warn "role=validator: adding $node_id to validators: — THIS CHANGES THE GENESIS ROOT."
    warn "Repeat this exact edit on EVERY node and WIPE every data dir before restart (fingerprint guard)."
    # Backup before mutating (§2 may have skipped its backup on no-op path).
    if [ ! -e "$NODE_YAML.bak.$TS" ]; then
      cp "$NODE_YAML" "$NODE_YAML.bak.$TS"
    fi
    if grep -qE '^[[:space:]]*validators:[[:space:]]*\[\]' "$NODE_YAML"; then
      python3 - "$NODE_YAML" "$node_id" <<'EOF' || die "failed to edit validators:"
import re, sys
path, nid = sys.argv[1:3]
src = open(path).read()
new, n = re.subn(r'(?m)^validators:\s*\[\]\s*$', f'validators:\n  - "{nid}"', src, count=1)
assert n == 1, "validators: [] anchor not found"
open(path, 'w').write(new)
EOF
    else
      grep -qE '^[[:space:]]*validators:' "$NODE_YAML" || die "$NODE_YAML has no validators: block"
      # Append after the last entry of the validators: block (the block is the
      # run of indented lines following the `validators:` header).
      python3 - "$NODE_YAML" "$node_id" <<'EOF' || die "failed to edit validators:"
import sys
path, nid = sys.argv[1:3]
lines = open(path).read().splitlines(keepends=True)
start = next(i for i, ln in enumerate(lines) if ln.startswith('validators:'))
end = start + 1
while end < len(lines) and (lines[end].startswith((' ', '\t')) or lines[end].strip() == ''):
    end += 1
lines.insert(end, f'  - "{nid}"\n')
open(path, 'w').write(''.join(lines))
EOF
    fi
    note "appended $node_id to validators: (backup $NODE_YAML.bak.$TS)"
  fi
fi

# --- 4. env: STELL_PEER_PQ_KEYS (idempotent, mode 600 kept) ---------------------
if [ -n "$pq_line" ]; then
  # Match inside the STELL_PEER_PQ_KEYS value only (a file-global grep could
  # false-positive on a comment or another variable containing the hex).
  if grep -E '^STELL_PEER_PQ_KEYS=' "$ENV_FILE" | grep -qF "$ed_pub"; then
    note "STELL_PEER_PQ_KEYS already maps $ed_pub; unchanged"
  else
    cp "$ENV_FILE" "$ENV_FILE.bak.$TS"
    if grep -qE '^STELL_PEER_PQ_KEYS=' "$ENV_FILE"; then
      # Append comma-separated; tolerate empty value and trailing whitespace.
      python3 - "$ENV_FILE" "$pq_line" <<'EOF' || die "failed to edit $ENV_FILE"
import re, sys
path, mapping = sys.argv[1:3]
src = open(path).read()
def add(m):
    cur = m.group(1).strip().strip('"').strip("'")
    cur = (cur + ',' + mapping) if cur else mapping
    return 'STELL_PEER_PQ_KEYS=' + cur
new, n = re.subn(r'(?m)^STELL_PEER_PQ_KEYS=(.*)$', add, src, count=1)
assert n == 1
open(path, 'w').write(new)
EOF
    else
      printf 'STELL_PEER_PQ_KEYS=%s\n' "$pq_line" >> "$ENV_FILE"
    fi
    chmod 600 "$ENV_FILE"
    note "appended PQ mapping for $peer_name to $ENV_FILE (backup $ENV_FILE.bak.$TS)"
  fi
fi

# --- 5. rolling-restart of ONE node ---------------------------------------------
if [ "$RESTART" = 1 ]; then
  [ -n "$UNIT" ] || die "--restart needs --unit NAME"
  if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl absent: restart $UNIT manually (systemctl restart $UNIT)"
  fi
  note "rolling-restart: systemctl restart $UNIT (single unit; the rest of the network keeps running)"
  systemctl restart "$UNIT" || die "systemctl restart $UNIT failed"
  sleep 3
  if systemctl is-active --quiet "$UNIT"; then
    note "$UNIT active after restart"
  else
    die "$UNIT not active after restart; backups at $NODE_YAML.bak.$TS and $ENV_FILE.bak.$TS; see journalctl -u $UNIT -e"
  fi
else
  if [ -n "$UNIT" ]; then
    note "files staged; when ready: systemctl restart $UNIT"
  else
    note "files staged; restart the node when ready (no --unit given, nothing restarted)"
  fi
fi

printf 'add-peer.sh: admitted %s (%s) as %s\n' "$peer_name" "$node_id" "$ROLE"
