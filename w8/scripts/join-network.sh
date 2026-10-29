#!/usr/bin/env bash
# join-network.sh — one-command onboarding of a new Stellereum node.
#
# Raises a validator/observer WITHOUT hours in the terminal:
#   1. generates keys (identity/e2e/falcon via the SAME `load_or_generate`
#      mechanism `run` uses: `stellereum keys init`)
#   2. prints the ready peer-stanza (node-id/ed-pub/x-pub/falcon-pub) for the
#      network admin to paste on their side (scripts/add-peer.sh)
#   3. builds node.yaml from a template + DNS seeds (seeds.stellereum.org)
#   4. writes the env file (mode 600), installs a systemd unit with safe
#      limits (MemoryMax/CPUQuota/Nice, prune retention, journal caps) and a
#      disk-guard cron job
#   5. opens UDP 9410 (or prints the exact firewall command when it cannot)
#   6. preflights the fresh join through `stellereum node-bootstrap --no-exec`
#      (clean data dir, STELL_OBSERVER=1, live peer pointer, non-empty
#      validators:) and only then starts the unit. First start goes through
#      `node-bootstrap` (which execs into run after the gate); restarts use
#      the `run` unit directly. Manual `cp -a` of another node's data/ is
#      never part of this flow.
#
# New nodes ALWAYS start as observers (STELL_OBSERVER=1): a fresh key must
# FOLLOW the existing chain, not mint its own genesis. Promoting to validator
# is a coordinated step afterwards (see docs/OPERATIONS.md §10).
#
# Usage:
#   scripts/join-network.sh --faucet-key <64hex> [options]
#
# Required:
#   --faucet-key HEX   network's shared STELL_FAUCET_KEY (64 hex chars).
#                      MUST match every other node byte-for-byte, or the
#                      genesis state root differs and this node runs a
#                      private chain. There is no handshake that catches it.
#
# Common options:
#   --home DIR         node home (node.yaml, env, keys/, data/). Default:
#                      $HOME/stellereum-node
#   --name NAME        node name in node.yaml. Default: stellereum-newnode
#   --advertise IP:PORT
#                      public address other nodes dial (UDP/QUIC). Default:
#                      autodetected first non-loopback IP + :9410
#   --listen ADDR:PORT QUIC listener. Default: 0.0.0.0:9410
#   --rpc ADDR:PORT    JSON-RPC listen. Default: 127.0.0.1:8545
#   --explorer ADDR:PORT
#                      gateway listen. Default: 127.0.0.1:8080
#   --seeds DOMAINS    STELL_DNS_SEEDS (discovery only, never validators).
#                      Default: seeds.stellereum.org
#   --peers-file FILE  copy `peers:` + `validators:` (the network's CURRENT
#                      validator set) from an admin-supplied file. Without it
#                      node.yaml ships with empty lists and the unit is
#                      installed but NOT started — the admin must supply the
#                      set first (otherwise this node derives its own solo
#                      genesis and splits silently).
#   --faucet-on        serve the faucet endpoint on this node (default off;
#                      enable on ONE node per network at most)
#   --validator        start as validator instead of observer (STELL_OBSERVER=0).
#                      Only correct when the admin ALREADY listed this node's
#                      id in every node's `validators:` AND all nodes were
#                      wiped/restarted for the new genesis. Default: observer.
#   --archive          keep every block body forever (default: prune with
#                      STELL_ARCHIVE=0 + STELL_KEEP_BLOCKS=1000000)
#   --service NAME     systemd unit name. Default: stellereum-node
#   --binary PATH      stellereum binary (default: auto-detect, else build)
#   --force            overwrite existing node.yaml/env (keys are NEVER
#                      overwritten: identity is stable across restarts)
#   --no-systemd       write files only, do not touch systemd
#   --no-cron          skip the disk-guard cron job
#   --no-firewall      skip the firewall attempt
#   -h|--help
#
# Exit codes: 0 ok (read the trailing NEXT STEPS even on 0: the node may be
# installed-but-not-started when --peers-file was omitted), 1 error, 2 usage.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOME_DIR="${STELL_HOME:-$HOME/stellereum-node}"
NAME="stellereum-newnode"
LISTEN="0.0.0.0:9410"
ADVERTISE=""
RPC="127.0.0.1:8545"
EXPLORER="127.0.0.1:8080"
METRICS="127.0.0.1:9401"
SEEDS="seeds.stellereum.org"
PEERS_FILE=""
FAUCET_KEY=""
FAUCET_ON=0
OBSERVER=1
ARCHIVE=0
KEEP_BLOCKS=1000000
SERVICE="stellereum-node"
BINARY=""
FORCE=0
WITH_SYSTEMD=1
WITH_CRON=1
WITH_FIREWALL=1

usage() {
  sed -n '2,/^set -uo/p' "$0" | sed 's/^# \{0,1\}//'
}

die() { printf 'join-network.sh: ERROR: %s\n' "$*" >&2; exit 1; }
warn() { printf 'join-network.sh: WARN: %s\n' "$*" >&2; }
note() { printf 'join-network.sh: %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --home) HOME_DIR="${2:?--home needs a directory}"; shift 2 ;;
    --name) NAME="${2:?--name needs a value}"; shift 2 ;;
    --advertise) ADVERTISE="${2:?--advertise needs IP:PORT}"; shift 2 ;;
    --listen) LISTEN="${2:?--listen needs ADDR:PORT}"; shift 2 ;;
    --rpc) RPC="${2:?--rpc needs ADDR:PORT}"; shift 2 ;;
    --explorer) EXPLORER="${2:?--explorer needs ADDR:PORT}"; shift 2 ;;
    --seeds) SEEDS="${2:?--seeds needs a domain list}"; shift 2 ;;
    --peers-file) PEERS_FILE="${2:?--peers-file needs a file}"; shift 2 ;;
    --faucet-key) FAUCET_KEY="${2:?--faucet-key needs 64 hex chars}"; shift 2 ;;
    --faucet-on) FAUCET_ON=1; shift ;;
    --validator) OBSERVER=0; shift ;;
    --archive) ARCHIVE=1; shift ;;
    --service) SERVICE="${2:?--service needs a name}"; shift 2 ;;
    --binary) BINARY="${2:?--binary needs a path}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --no-systemd) WITH_SYSTEMD=0; shift ;;
    --no-cron) WITH_CRON=0; shift ;;
    --no-firewall) WITH_FIREWALL=0; shift ;;
    -h|--help) usage; exit 2 ;;
    *) printf 'join-network.sh: unknown argument %s (see --help)\n' "$1" >&2; exit 2 ;;
  esac
done

[ -n "$FAUCET_KEY" ] || { usage >&2; die "missing --faucet-key (must match the network byte-for-byte)"; }
case "$FAUCET_KEY" in
  *[!0-9a-fA-F]*|"") die "--faucet-key must be hex" ;;
esac
[ "${#FAUCET_KEY}" = 64 ] || die "--faucet-key must be 64 hex chars (32 bytes), got ${#FAUCET_KEY}"
case "$FAUCET_KEY" in
  PLACEHOLDER*) die "--faucet-key is still the placeholder from testnet/genesis.env" ;;
esac
if [ -n "$PEERS_FILE" ] && [ ! -f "$PEERS_FILE" ]; then
  die "--peers-file $PEERS_FILE not found"
fi

# --- 0. directories + permissions (0700 dirs, 0600 secrets) -------------------
mkdir -p "$HOME_DIR/keys" "$HOME_DIR/data"
chmod 700 "$HOME_DIR" "$HOME_DIR/keys" "$HOME_DIR/data"
# Fresh-bootstrap rule (enforced again by `stellereum node-bootstrap`): a new
# node joins with a CLEAN data dir and syncs (snapshot incl. ledger + walk),
# NEVER by copying another node's data/ over ssh. A leftover store here means
# this is a re-run/restart, not a fresh join.
if [ -e "$HOME_DIR/data/store" ] || [ -e "$HOME_DIR/data/kv.json" ]; then
  warn "existing chain data in $HOME_DIR/data (store/kv.json present): a FRESH join needs the whole data dir wiped first; node-bootstrap refuses dirty dirs (use --allow-dirty only for restarts, never to paper over a foreign chain)"
fi

# --- 1. binary ----------------------------------------------------------------
if [ -z "$BINARY" ]; then
  for cand in "$SCRIPT_DIR/../target/release/stellereum" "./target/release/stellereum" "$HOME/stellereum/target/release/stellereum"; do
    if [ -x "$cand" ]; then BINARY="$cand"; break; fi
  done
fi
if [ -z "$BINARY" ] || [ ! -x "$BINARY" ]; then
  if command -v stellereum >/dev/null 2>&1; then
    BINARY="$(command -v stellereum)"
  elif command -v cargo >/dev/null 2>&1; then
    note "no binary found; building with cargo (this takes a while)..."
    ( cd "$SCRIPT_DIR/.." && cargo build --release --bin stellereum ) || die "cargo build failed"
    BINARY="$SCRIPT_DIR/../target/release/stellereum"
  else
    die "no stellereum binary (tried target/release, PATH) and no cargo to build one"
  fi
fi
note "binary: $BINARY"

# --- 2. keys via the existing load_or_generate mechanism ----------------------
# Node private keys are ENCRYPTED AT REST by default: the node refuses to
# write a plaintext keystore unless the operator explicitly sets
# STELL_KEY_PLAINTEXT=1. So the passphrase has to exist BEFORE the keys are
# generated. It is minted here (or reused from the env file) and exported for
# `keys init`; it is written into the env file (0600) further down, so the
# systemd unit has it on every start.
ENV_FILE="$HOME_DIR/node.env"
KEY_PASSPHRASE=""
if [ -f "$ENV_FILE" ]; then
  KEY_PASSPHRASE="$(sed -n 's/^STELL_KEY_PASSPHRASE=//p' "$ENV_FILE" | head -1)"
fi
if [ -z "$KEY_PASSPHRASE" ] && [ -n "${STELL_KEY_PASSPHRASE:-}" ]; then
  KEY_PASSPHRASE="$STELL_KEY_PASSPHRASE"
fi
if [ -z "$KEY_PASSPHRASE" ]; then
  KEY_PASSPHRASE="$(head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '/+' '_-')"
fi
export STELL_KEY_PASSPHRASE="$KEY_PASSPHRASE"
note "key passphrase: minted/reused (written to $ENV_FILE, 0600, further down)"

# `keys init` is idempotent: existing keys are loaded, never overwritten.
if "$BINARY" keys init --keys-dir "$HOME_DIR/keys" >/tmp/stell-join-ident.$$ 2>/tmp/stell-join-ident.err.$$; then
  IDENT_LINE="$(grep -m1 'NODE IDENTITY' /tmp/stell-join-ident.$$ || true)"
  rm -f /tmp/stell-join-ident.$$ /tmp/stell-join-ident.err.$$
  [ -n "$IDENT_LINE" ] || die "keys init printed no NODE IDENTITY line"
else
  # Fallback for binaries predating the `keys` subcommand: one short run with
  # an empty config generates the same keys, then we stop the node.
  warn "`keys init` unavailable ($BINARY may be old); falling back to a short run"
  rm -f /tmp/stell-join-ident.$$ /tmp/stell-join-ident.err.$$
  printf 'name: %s\nlisten: "127.0.0.1:9499"\npeers: []\n' "$NAME" > "$HOME_DIR/node.yaml.tmpkeys"
  ( cd "$HOME_DIR" && timeout 20 "$BINARY" run --config node.yaml.tmpkeys --shard 1 > /tmp/stell-join-ident.$$ 2>&1 ) || true
  pkill -f "stellereum run --config node.yaml.tmpkeys" 2>/dev/null || true
  IDENT_LINE="$(grep -m1 -o 'NODE IDENTITY: .*' /tmp/stell-join-ident.$$ || true)"
  rm -f "$HOME_DIR/node.yaml.tmpkeys" /tmp/stell-join-ident.$$
  [ -n "$IDENT_LINE" ] || die "could not generate keys (neither `keys init` nor the fallback run worked)"
fi
chmod 700 "$HOME_DIR/keys"
chmod 600 "$HOME_DIR"/keys/* 2>/dev/null || true
note "$IDENT_LINE"

# --- 3. peer-stanza for the admin ---------------------------------------------
STANZA_FILE="$HOME_DIR/peer-stanza.txt"
if [ "$OBSERVER" = 1 ]; then
  ROLE_NOTE="observer (STELL_OBSERVER=1): follows the chain, never proposes/votes"
else
  ROLE_NOTE="validator (STELL_OBSERVER=0): only correct if the admin already listed this id everywhere"
fi
{
  echo "# STELLEREUM peer-stanza for '$NAME' ($ROLE_NOTE)"
  echo "# Generated $(date -u +%FT%TZ). Send this whole block to the network admin;"
  echo "# they feed it to scripts/add-peer.sh. Public keys only — no secrets here."
  echo "#"
  if "$BINARY" keys peer-stanza --keys-dir "$HOME_DIR/keys" --name "$NAME" --endpoint "${ADVERTISE:-REPLACE_WITH_PUBLIC_IP:9410}" 2>/dev/null | grep -v 'WARN'; then
    true
  else
    echo "# (peer-stanza subcommand unavailable; identity line is above — derive the stanza from it)"
  fi
} > "$STANZA_FILE"
chmod 644 "$STANZA_FILE"
printf '\n===== PEER STANZA (send to the network admin) =====\n'
cat "$STANZA_FILE"
printf '===== end of stanza (also saved at %s) =====\n\n' "$STANZA_FILE"

# --- 4. advertise address ------------------------------------------------------
P2P_PORT="${LISTEN##*:}"
if [ -z "$ADVERTISE" ]; then
  LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  if [ -n "$LAN_IP" ]; then
    ADVERTISE="$LAN_IP:$P2P_PORT"
    warn "no --advertise given; using $ADVERTISE (fix it if the node is behind NAT)"
  else
    ADVERTISE="REPLACE_WITH_PUBLIC_IP:$P2P_PORT"
    warn "could not autodetect an IP; edit 'advertise:' in $HOME_DIR/node.yaml"
  fi
fi

# --- 5. node.yaml from template + seeds ---------------------------------------
YAML="$HOME_DIR/node.yaml"
if [ -f "$YAML" ] && [ "$FORCE" = 0 ]; then
  note "$YAML exists; keeping it (use --force to regenerate)"
else
  [ ! -f "$YAML" ] || cp "$YAML" "$YAML.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  if [ -n "$PEERS_FILE" ]; then
    # Copy the network's CURRENT validator set verbatim: the set must be a pure
    # function of this file or the genesis root differs and we split silently.
    # Extract peers:/validators: blocks with python3 when available, else awk.
    if command -v python3 >/dev/null 2>&1; then
      PEERS_BLOCK="$(python3 - "$PEERS_FILE" <<'EOF'
import re,sys
src=open(sys.argv[1]).read()
out=["## peers:/validators: copied from --peers-file "+sys.argv[1]+" ##\n"]
for key in ("peers:","validators:"):
    m=re.search(r'(?m)^'+key+r'\s*\n((?:[ \t]+.*\n|\s*\n)*)',src)
    out.append(key+"\n")
    block=m.group(1) if m and m.group(1).strip() else "  []\n"
    out.append(block if block.endswith("\n") else block+"\n")
print(''.join(out))
EOF
)" || die "could not extract peers:/validators: from $PEERS_FILE"
    else
      PEERS_BLOCK="$(awk '/^peers:/,/^[^ ]/{print} /^validators:/,/^[^ ]/{print}' "$PEERS_FILE")"
    fi
  else
    PEERS_BLOCK="peers: []
# validators: filled by the admin (see NEXT STEPS below). Empty here means
# this file alone would derive a SOLO genesis — the unit is therefore NOT
# started until the set is in place.
validators: []"
  fi
  cat > "$YAML" <<EOF
# Stellereum node config generated by scripts/join-network.sh on $(date -u +%FT%TZ).
# Schema: infnode NodeConfig (kebab-case). Required: name, listen, peers.
name: $NAME
listen: "$LISTEN"
advertise: "$ADVERTISE"
storage-roles:
  - mail
  - files
# 2 = info: FINALIZED lines and view-change lines are both info level, and
# they are the only two things distinguishing a healthy node from a stuck one.
log-level: 2
metrics-listen: "$METRICS"
# TOFU for discovery only: unknown peers get read-only DHT capabilities.
# Discovery peers are NEVER validators (see STELL_DNS_SEEDS in the env file),
# so poisoning discovery cannot touch the quorum or the genesis root.
allow-unknown: true
unknown-allow:
  - "dht.lookup"
  - "dht.update"
  - "dht.find_node"
  - "dht.find_value"
$PEERS_BLOCK
EOF
  chmod 644 "$YAML"
  note "wrote $YAML"
fi

# --- 6. env file (0600): identical genesis inputs, local policy ---------------
if [ -f "$ENV_FILE" ] && [ "$FORCE" = 0 ]; then
  note "$ENV_FILE exists; keeping it (use --force to regenerate)"
  # A legacy env file has no passphrase line. The keys may already have been
  # upgraded to enc2: by `keys init` above, so the passphrase MUST land in the
  # env file, or the node cannot decrypt its own identity on the next start.
  if ! grep -q '^STELL_KEY_PASSPHRASE=' "$ENV_FILE"; then
    printf '\n# KEY PASSPHRASE — decrypts the node private keys in ./keys (enc2: Argon2id\n# + XChaCha20-Poly1305). Losing it means losing the node identity.\nSTELL_KEY_PASSPHRASE=%s\n' \
      "$KEY_PASSPHRASE" >> "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    note "appended STELL_KEY_PASSPHRASE to $ENV_FILE (0600)"
  fi
else
  [ ! -f "$ENV_FILE" ] || cp "$ENV_FILE" "$ENV_FILE.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  FAUCET_FLAG=0; [ "$FAUCET_ON" = 1 ] && FAUCET_FLAG=1
  cat > "$ENV_FILE" <<EOF
# Stellereum node environment generated by scripts/join-network.sh.
# Sourced with: set -a; . $ENV_FILE; set +a
# GENESIS INPUTS (must be identical on every node of the network):
STELL_FAUCET_KEY=$FAUCET_KEY
# LOCAL POLICY (may differ per node; written out explicitly anyway):
STELL_OBSERVER=$OBSERVER
STELL_FAUCET=$FAUCET_FLAG
STELL_RPC_LISTEN=$RPC
STELL_EXPLORER_LISTEN=$EXPLORER
STELL_DNS_SEEDS=$SEEDS
STELL_MIN_BLOCK_MS=400
STELL_MIN_GAS_LIMIT=280000
STELL_ARCHIVE=$ARCHIVE
STELL_KEEP_BLOCKS=$KEEP_BLOCKS
STELL_RPC_AUTH_TOKEN=
STELL_FAUCET_TOKEN=
# KEY PASSPHRASE — decrypts the node private keys in ./keys (enc2: Argon2id
# + XChaCha20-Poly1305). Losing it means losing the node identity: back it
# up together with ./keys, and never paste it anywhere.
STELL_KEY_PASSPHRASE=$KEY_PASSPHRASE
EOF
  chmod 600 "$ENV_FILE"
  note "wrote $ENV_FILE (0600)"
fi

READY_TO_START=1
if [ -z "$PEERS_FILE" ]; then
  READY_TO_START=0
fi

# --- 7. systemd unit with safe limits + journal caps ---------------------------
UNIT_FILE="/etc/systemd/system/$SERVICE.service"
if [ "$WITH_SYSTEMD" = 1 ]; then
  if [ "$(id -u)" != 0 ]; then
    warn "not root: skipping systemd install (run with sudo or --no-systemd)"
    WITH_SYSTEMD=0
  elif ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl absent: skipping systemd install"
    WITH_SYSTEMD=0
  else
    [ -f "$UNIT_FILE" ] && cp "$UNIT_FILE" "$UNIT_FILE.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Stellereum node $NAME (onboarded by join-network.sh)
Documentation=file:$SCRIPT_DIR/../docs/OPERATIONS.md
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$HOME_DIR
# No leading "-": a missing env file must FAIL the unit instead of starting
# with wrong ports / missing STELL_FAUCET_KEY (which would silently change
# the genesis root).
EnvironmentFile=$ENV_FILE
ExecStart=$BINARY run --config node.yaml --shard 1
Restart=always
RestartSec=5
# Safe limits: observed RSS is tens of MB; 2G stops a runaway node from
# OOM-killing its neighbours. 80% of one CPU keeps sshd/journald responsive.
MemoryMax=2G
CPUQuota=80%
Nice=5
# Stdout/stderr go to the journal (rotated, rate-limited) — never to an
# ever-growing run.log.
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE
# Journal caps for this unit's stream: 100MB per service, rate-limited logs
# (a view-change storm must not fill the disk).
LogRateLimitIntervalSec=5s
LogRateLimitBurst=1000
SystemCallArchitectures=native
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$UNIT_FILE"
    # Cap the journal itself (system-wide, one drop-in; harmless if present).
    mkdir -p /etc/systemd/journald.conf.d
    if [ ! -f /etc/systemd/journald.conf.d/stellereum-caps.conf ]; then
      cat > /etc/systemd/journald.conf.d/stellereum-caps.conf <<'EOF'
[Journal]
# Disk-guard: the journal shares the disk with ./data/store (archive nodes
# grow without bound). Rotate early, keep little.
SystemMaxUse=500M
RuntimeMaxUse=200M
MaxFileSec=7day
EOF
    fi
    # Rotate any legacy current.log next to the home dir (copytruncate: the
    # node may hold it open across the whole run).
    if [ ! -f /etc/logrotate.d/stellereum-"$SERVICE" ]; then
      cat > /etc/logrotate.d/stellereum-"$SERVICE" <<EOF
$HOME_DIR/current.log {
    size 50M
    rotate 7
    compress
    copytruncate
    missingok
    notifempty
}
EOF
    fi
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1 || true
    note "installed systemd unit $SERVICE"
  fi
fi

# --- 8. disk-guard cron (prune-mode nodes still need a watcher) ----------------
if [ "$WITH_CRON" = 1 ]; then
  GUARD_BIN="/usr/local/bin/stellereum-disk-guard"
  if [ "$(id -u)" = 0 ]; then
    cat > "$GUARD_BIN" <<EOF
#!/usr/bin/env bash
# stellereum-disk-guard (installed by join-network.sh): read-only disk watch.
# Alerts to the journal when the disk or the store grows hot. Writes nothing.
set -u
HOME_DIR="$HOME_DIR"
USE_PCT=\$(df -P "\$HOME_DIR" 2>/dev/null | awk 'NR==2 { gsub(/%/, "", \$5); print \$5 }')
STORE_DU=\$(du -sh "\$HOME_DIR/data/store" 2>/dev/null | cut -f1 || echo unknown)
case "\$USE_PCT" in ''|*[!0-9]*) exit 0 ;; esac
if [ "\$USE_PCT" -ge 90 ]; then
  logger -t stellereum-disk-guard "CRITICAL: disk \$USE_PCT% full (store \$STORE_DU). Free the journal/vacuum logs; do NOT delete data/store, data/kv.json or data/mail.key individually."
elif [ "\$USE_PCT" -ge 80 ]; then
  logger -t stellereum-disk-guard "warning: disk \$USE_PCT% full (store \$STORE_DU)"
fi
EOF
    chmod 755 "$GUARD_BIN"
    printf '*/15 * * * * root %s >/dev/null 2>&1\n' "$GUARD_BIN" > /etc/cron.d/stellereum-disk-guard
    chmod 644 /etc/cron.d/stellereum-disk-guard
    note "installed disk-guard cron (every 15 min, warn>=80% crit>=90%)"
  else
    warn "not root: skipping cron install"
  fi
fi

# --- 9. firewall: UDP P2P port must be reachable --------------------------------
if [ "$WITH_FIREWALL" = 1 ]; then
  if command -v ufw >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
    if ufw status 2>/dev/null | grep -qi active; then
      ufw allow "$P2P_PORT"/udp >/dev/null 2>&1 && note "ufw: allowed $P2P_PORT/udp" \
        || warn "ufw allow failed; open UDP $P2P_PORT manually"
    else
      warn "ufw installed but inactive; ensure UDP $P2P_PORT is reachable"
    fi
  elif command -v iptables >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
    iptables -C INPUT -p udp --dport "$P2P_PORT" -j ACCEPT 2>/dev/null \
      || iptables -I INPUT -p udp --dport "$P2P_PORT" -j ACCEPT 2>/dev/null \
      && note "iptables: allowed UDP $P2P_PORT" \
      || warn "iptables change failed; open UDP $P2P_PORT manually"
  else
    warn "no firewall tool (or not root): ensure UDP $P2P_PORT is open inbound (QUIC P2P)"
  fi
fi

# --- 10. start (only when the validator set is in place) -----------------------
# Fresh joins start through the bootstrap gate, not raw `run`: `node-bootstrap`
# re-checks (clean dir, STELL_OBSERVER=1, faucet key, live peer pointer,
# non-empty validators:) and only then execs into the SAME `run` sync engine
# (snapshot-sync incl. ledger + all domains → body walk → live). Restarts keep
# using the systemd `run` unit directly — re-gating a dirty dir on every
# restart would be wrong, which is why the unit stays on `run`.
if [ "$WITH_SYSTEMD" = 1 ] && [ "$READY_TO_START" = 1 ]; then
  if "$BINARY" node-bootstrap --help >/dev/null 2>&1; then
    if ( cd "$HOME_DIR" && set -a && . ./node.env && set +a \
         && "$BINARY" node-bootstrap --config node.yaml --shard 1 --no-exec ); then
      note "bootstrap preflight passed (clean dir, observer, peer pointer, validator set)"
    else
      die "bootstrap preflight FAILED (see [bootstrap] lines above). Fix the cause — NEVER copy another node's data/ directory instead (a foreign store carries a foreign genesis fingerprint and splits silently)"
    fi
  else
    warn "binary predates 'node-bootstrap'; skipping the preflight gate (rebuild to get it: cargo build --release --bin stellereum)"
  fi
  if systemctl start "$SERVICE"; then
    sleep 3
    systemctl is-active --quiet "$SERVICE" && note "service $SERVICE started" \
      || die "service $SERVICE failed to stay up; see journalctl -u $SERVICE -e"
  else
    die "systemctl start $SERVICE failed"
  fi
fi

printf '\n===== NEXT STEPS =====\n'
if [ "$READY_TO_START" = 0 ]; then
  printf '1. This node is NOT started yet: node.yaml has empty peers:/validators:.\n'
  printf '   Ask the network admin for the current validator set (a peers file\n'
  printf '   or the node.yaml of a live node), then re-run with:\n'
  printf '     %s --home %s --faucet-key <SAME KEY> --peers-file <admin file> [--force]\n' "$0" "$HOME_DIR"
  printf '   Until then this node would derive a SOLO genesis and split silently.\n'
else
  printf '1. Service %s is installed%s.\n' "$SERVICE" "$([ "$WITH_SYSTEMD" = 1 ] && echo " and started" || echo " (files only)")"
fi
printf '2. Send %s to the network admin.\n' "$STANZA_FILE"
printf '   They run: scripts/add-peer.sh --node-yaml <their node.yaml> --env-file <their env> %s\n' "$STANZA_FILE"
printf '3. This node runs as %s. First start goes through the bootstrap gate:\n' "$([ "$OBSERVER" = 1 ] && echo "OBSERVER (STELL_OBSERVER=1)" || echo "VALIDATOR")"
printf '     ( cd %s && set -a; . ./node.env; set +a && <binary> node-bootstrap --config node.yaml --shard 1 )\n' "$HOME_DIR"
printf '   which preflights (clean dir / observer / peer pointer / validator set)\n'
printf '   and then execs into run: snapshot-sync (state + all domains incl. the\n'
printf '   staking ledger, root-checked before commit) -> body walk -> live.\n'
printf '   NEVER cp -a another node'"'"'s data/ directory: a foreign store carries\n"
printf '   a foreign genesis fingerprint and the node splits silently instead of\n'
printf '   joining. Watch sync with:\n'
printf '     journalctl -u %s -f   # look for: [sync] caught up N blocks\n' "$SERVICE"
printf '     curl -s -X POST http://%s -H "content-type: application/json" -d "{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1,\\"method\\":\\"stell_syncing\\",\\"params\\":[]}"\n' "$RPC"
printf '   Compare stell_getStateRoot + stell_blockNumber against a live peer:\n'
printf '   equal roots at equal heights = same chain. Different roots = STOP, do not transact.\n'
printf '4. Becoming a validator afterwards is COORDINATED (genesis changes when\n'
printf '   the set changes): see docs/OPERATIONS.md §10. Never just flip\n'
printf '   STELL_OBSERVER=0 on a live chain and hope.\n'
printf '5. Secrets: %s (0600) and %s/* (0600/0700). Never commit or paste them.\n' "$ENV_FILE" "$HOME_DIR/keys"
printf '   The node keys in %s/keys are ENCRYPTED (enc2: Argon2id + XChaCha20-Poly1305);\n' "$HOME_DIR"
printf '   the passphrase lives in %s (STELL_KEY_PASSPHRASE). Back both up TOGETHER:\n' "$ENV_FILE"
printf '   a key backup without the passphrase is a backup of ciphertext. See\n'
printf '   docs/OPERATIONS.md §11.\n'
