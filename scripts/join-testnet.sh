#!/usr/bin/env bash
# ==============================================================================
# join-testnet.sh — External operator onboarding for the Stellereum testnet
#
# Supports two roles:
#   --mode observer   Run a full non-validating observer node (RPC + state sync)
#   --mode validator  Prepare a validator node (cold withdrawal.key + hot
#                     falcon.key via `stellereum keys init`, node.yaml, node.env,
#                     snapshot bootstrap, and registration instructions)
#
# Note: the public faucet is capped at 50 STELL and cannot fund the 1,100 STELL
# validator bond. Validator stake is provisioned by the Foundation on request
# or by an operator transfer.
#
# Usage:
#   scripts/join-testnet.sh --mode observer [OPTIONS]
#   scripts/join-testnet.sh --mode validator [OPTIONS]
#   scripts/join-testnet.sh                  (interactive prompts on a TTY)
#
# Options:
#   --mode MODE             observer | validator
#   --home DIR              Node home directory
#                           (default: $HOME/stell-observer or $HOME/stell-validator)
#   --name NAME             Node name in node.yaml
#   --listen ADDR:PORT      P2P QUIC listen address (default: 0.0.0.0:9411 observer,
#                           0.0.0.0:9410 validator)
#   --advertise IP:PORT     Public P2P address advertised to peers
#   --rpc ADDR:PORT         JSON-RPC listen address (default: 127.0.0.1:8545)
#   --explorer ADDR:PORT    Explorer/gateway listen address (default: 127.0.0.1:8080)
#   --seeds DOMAINS         STELL_DNS_SEEDS (default: seeds.stellereum.org)
#   --peers-file FILE       Custom YAML peers list (default: live nodeA + nodeD)
#   --snapshot-url URL      Snapshot archive URL
#                           (default: https://rpc.stellereum.org/snapshot/latest.tar.zst)
#   --sha256-url URL        Snapshot SHA-256 checksum URL
#                           (default: <snapshot-url>.sha256)
#   --require-sha256        Fail if snapshot SHA-256 checksum is unavailable
#   --refresh-store         Backup and replace an existing data/store from snapshot
#   --skip-snapshot         Do not download the HTTP snapshot
#   --binary PATH           Path to stellereum binary (default: auto-detect)
#   --chain-id ID           Target chain ID (default: 5757)
#   --commission-bps N      Initial validator commission bps 0..10000 (default: 1000)
#   --force                 Overwrite existing node.yaml and node.env (keys preserved)
#   --start                 Start the node immediately after setup completes
#   --non-interactive       Disable interactive prompts
#   -h, --help              Show this help
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE=""
HOME_DIR=""
NAME=""
LISTEN=""
ADVERTISE=""
RPC="127.0.0.1:8545"
EXPLORER="127.0.0.1:8080"
SEEDS="seeds.stellereum.org"
PEERS_FILE=""
SNAPSHOT_URL="https://rpc.stellereum.org/snapshot/latest.tar.zst"
SHA256_URL=""
SHA256_URL_SET=0
REQUIRE_SHA256=0
REFRESH_STORE=0
SKIP_SNAPSHOT=0
BINARY="${STELL_BIN:-}"
CHAIN_ID="5757"
COMMISSION_BPS="1000"
FORCE=0
START_NOW=0
NON_INTERACTIVE=0

log()  { printf '\033[1;34m[join-testnet]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,/^# ====/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="${2:?--mode requires observer or validator}"; shift 2 ;;
        --mode=*) MODE="${1#--mode=}"; shift ;;
        --home) HOME_DIR="${2:?--home requires a directory}"; shift 2 ;;
        --home=*) HOME_DIR="${1#--home=}"; shift ;;
        --name) NAME="${2:?--name requires a value}"; shift 2 ;;
        --name=*) NAME="${1#--name=}"; shift ;;
        --listen) LISTEN="${2:?--listen requires ADDR:PORT}"; shift 2 ;;
        --listen=*) LISTEN="${1#--listen=}"; shift ;;
        --advertise) ADVERTISE="${2:?--advertise requires IP:PORT}"; shift 2 ;;
        --advertise=*) ADVERTISE="${1#--advertise=}"; shift ;;
        --rpc) RPC="${2:?--rpc requires ADDR:PORT}"; shift 2 ;;
        --rpc=*) RPC="${1#--rpc=}"; shift ;;
        --explorer) EXPLORER="${2:?--explorer requires ADDR:PORT}"; shift 2 ;;
        --explorer=*) EXPLORER="${1#--explorer=}"; shift ;;
        --seeds) SEEDS="${2:?--seeds requires a domain list}"; shift 2 ;;
        --seeds=*) SEEDS="${1#--seeds=}"; shift ;;
        --peers-file) PEERS_FILE="${2:?--peers-file requires a path}"; shift 2 ;;
        --peers-file=*) PEERS_FILE="${1#--peers-file=}"; shift ;;
        --snapshot-url) SNAPSHOT_URL="${2:?--snapshot-url requires a URL}"; shift 2 ;;
        --snapshot-url=*) SNAPSHOT_URL="${1#--snapshot-url=}"; shift ;;
        --sha256-url) SHA256_URL="${2:?--sha256-url requires a URL}"; SHA256_URL_SET=1; shift 2 ;;
        --sha256-url=*) SHA256_URL="${1#--sha256-url=}"; SHA256_URL_SET=1; shift ;;
        --require-sha256) REQUIRE_SHA256=1; shift ;;
        --refresh-store) REFRESH_STORE=1; shift ;;
        --skip-snapshot) SKIP_SNAPSHOT=1; shift ;;
        --binary) BINARY="${2:?--binary requires a path}"; shift 2 ;;
        --binary=*) BINARY="${1#--binary=}"; shift ;;
        --chain-id) CHAIN_ID="${2:?--chain-id requires an integer}"; shift 2 ;;
        --chain-id=*) CHAIN_ID="${1#--chain-id=}"; shift ;;
        --commission-bps) COMMISSION_BPS="${2:?--commission-bps requires 0..10000}"; shift 2 ;;
        --commission-bps=*) COMMISSION_BPS="${1#--commission-bps=}"; shift ;;
        --force) FORCE=1; shift ;;
        --start) START_NOW=1; shift ;;
        --non-interactive) NON_INTERACTIVE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'join-testnet.sh: unknown argument %s (try --help)\n' "$1" >&2; exit 2 ;;
    esac
done

prompt_default() {
    local prompt_text="$1" default_val="$2" reply=""
    printf '%s [%s]: ' "$prompt_text" "$default_val" >&2
    IFS= read -r reply || true
    if [[ -z "$reply" ]]; then
        printf '%s' "$default_val"
    else
        printf '%s' "$reply"
    fi
}

# Interactive wizard when --mode is omitted on a TTY
if [[ -z "$MODE" ]]; then
    if [[ "$NON_INTERACTIVE" == "1" || ! -t 0 ]]; then
        usage >&2
        die "missing --mode (specify --mode observer or --mode validator)"
    fi
    printf 'Select node mode:\n  1) observer  (verify chain, serve RPC/explorer, no stake)\n  2) validator (prepare keys + snapshot + register-validator)\n' >&2
    choice="$(prompt_default "Choice (1 or 2)" "1")"
    case "$choice" in
        1|observer) MODE="observer" ;;
        2|validator) MODE="validator" ;;
        *) die "invalid choice '$choice' (expected 1/observer or 2/validator)" ;;
    esac
fi

case "$MODE" in
    observer|validator) ;;
    *) die "invalid --mode '$MODE' (expected observer or validator)" ;;
esac

if ! [[ "$CHAIN_ID" =~ ^[0-9]+$ ]]; then
    die "--chain-id must be an unsigned integer (got '$CHAIN_ID')"
fi
if ! [[ "$COMMISSION_BPS" =~ ^[0-9]+$ ]] || (( COMMISSION_BPS > 10000 )); then
    die "--commission-bps must be an integer in 0..10000 (got '$COMMISSION_BPS')"
fi
if [[ -n "$PEERS_FILE" && ! -f "$PEERS_FILE" ]]; then
    die "--peers-file '$PEERS_FILE' not found"
fi

if [[ -z "$HOME_DIR" ]]; then
    if [[ "$MODE" == "observer" ]]; then
        HOME_DIR="$HOME/stell-observer"
    else
        HOME_DIR="$HOME/stell-validator"
    fi
    if [[ "$NON_INTERACTIVE" == "0" && -t 0 && -z "${STELL_HOME:-}" ]]; then
        HOME_DIR="$(prompt_default "Node home directory" "$HOME_DIR")"
    fi
fi

if [[ -z "$NAME" ]]; then
    default_host="$(hostname -s 2>/dev/null || echo node)"
    if [[ "$MODE" == "observer" ]]; then
        NAME="observer-$default_host"
    else
        NAME="validator-$default_host"
    fi
    if [[ "$NON_INTERACTIVE" == "0" && -t 0 ]]; then
        NAME="$(prompt_default "Node name" "$NAME")"
    fi
fi

if [[ -z "$LISTEN" ]]; then
    if [[ "$MODE" == "observer" ]]; then
        LISTEN="0.0.0.0:9411"
    else
        LISTEN="0.0.0.0:9410"
    fi
fi

P2P_PORT="${LISTEN##*:}"
if [[ -z "$ADVERTISE" ]]; then
    detected_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    if [[ -n "$detected_ip" ]]; then
        default_adv="${detected_ip}:${P2P_PORT}"
    else
        default_adv="REPLACE_WITH_PUBLIC_IP:${P2P_PORT}"
    fi
    if [[ "$NON_INTERACTIVE" == "0" && -t 0 ]]; then
        ADVERTISE="$(prompt_default "Public P2P advertise address (IP:PORT)" "$default_adv")"
    else
        ADVERTISE="$default_adv"
    fi
fi

# Locate stellereum binary
if [[ -z "$BINARY" ]]; then
    for cand in \
        "$ROOT_DIR/stellereum/target/release/stellereum" \
        "$ROOT_DIR/stellereum/target/debug/stellereum" \
        "$(command -v stellereum 2>/dev/null || true)"; do
        if [[ -n "$cand" && -x "$cand" ]]; then
            BINARY="$cand"
            break
        fi
    done
fi
[[ -n "$BINARY" && -x "$BINARY" ]] || die "stellereum binary not found. Build it first ('cargo build --release' in stellereum/) or pass --binary PATH."

log "mode=$MODE home=$HOME_DIR name=$NAME binary=$BINARY"

mkdir -p "$HOME_DIR/keys" "$HOME_DIR/data"
chmod 700 "$HOME_DIR" "$HOME_DIR/keys" "$HOME_DIR/data"

ENV_FILE="$HOME_DIR/node.env"
KEY_PASSPHRASE=""
if [[ -f "$ENV_FILE" ]]; then
    KEY_PASSPHRASE="$(sed -n 's/^STELL_KEY_PASSPHRASE=//p' "$ENV_FILE" | head -1)"
fi
if [[ -z "$KEY_PASSPHRASE" && -n "${STELL_KEY_PASSPHRASE:-}" ]]; then
    KEY_PASSPHRASE="$STELL_KEY_PASSPHRASE"
fi
if [[ -z "$KEY_PASSPHRASE" ]]; then
    KEY_PASSPHRASE="$(head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '/+' '_-')"
    log "minted keystore passphrase (will be saved with mode 0600 in $ENV_FILE)"
else
    log "reusing existing keystore passphrase"
fi
export STELL_KEY_PASSPHRASE="$KEY_PASSPHRASE"

# 1. Generate node keys (encrypted at rest; never overwrites existing keys)
log "initializing node identity and hot Falcon-512 key in $HOME_DIR/keys..."
"$BINARY" keys init --keys-dir "$HOME_DIR/keys"

WITHDRAWAL_ADDRESS=""
VALIDATOR_ID=""
if [[ "$MODE" == "validator" ]]; then
    log "initializing cold withdrawal Falcon-512 key ($HOME_DIR/keys/withdrawal.key)..."
    "$BINARY" keys init --keys-dir "$HOME_DIR/keys" --falcon-file "$HOME_DIR/keys/withdrawal.key"

    STANZA_FILE="$HOME_DIR/peer-stanza.txt"
    "$BINARY" keys peer-stanza \
        --keys-dir "$HOME_DIR/keys" \
        --name "$NAME" \
        --endpoint "$ADVERTISE" > "$STANZA_FILE" 2>/dev/null || true
    chmod 644 "$STANZA_FILE" 2>/dev/null || true

    dry_out="$("$BINARY" validator register-validator \
        --withdrawal-key-file "$HOME_DIR/keys/withdrawal.key" \
        --voting-key-file "$HOME_DIR/keys/falcon.key" \
        --amount 1100000000000 \
        --commission-bps "$COMMISSION_BPS" \
        --chain-id "$CHAIN_ID" \
        --nonce 0 \
        --dry-run 2>/dev/null || true)"
    VALIDATOR_ID="$(printf '%s\n' "$dry_out" | sed -n 's/^[[:space:]]*Validator ID:[[:space:]]*//p' | head -1)"
    WITHDRAWAL_ADDRESS="$(printf '%s\n' "$dry_out" | sed -n 's/^[[:space:]]*Withdrawal Address:[[:space:]]*//p' | head -1)"
fi
chmod 700 "$HOME_DIR/keys"
chmod 600 "$HOME_DIR"/keys/* 2>/dev/null || true

# 2. Generate node.yaml
YAML_FILE="$HOME_DIR/node.yaml"
if [[ -f "$YAML_FILE" && "$FORCE" == "0" ]]; then
    log "$YAML_FILE already exists; keeping it (pass --force to regenerate)"
else
    if [[ -f "$YAML_FILE" ]]; then
        cp "$YAML_FILE" "$YAML_FILE.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    {
        cat << EOF
# Stellereum node config generated by scripts/join-testnet.sh on $(date -u +%FT%TZ)
name: $NAME
listen: "$LISTEN"
advertise: "$ADVERTISE"
storage-roles:
  - mail
  - files
log-level: 2
allow-unknown: true
unknown-allow:
  - "dht.lookup"
  - "dht.update"
  - "dht.find_node"
  - "dht.find_value"
validators: []
peers:
EOF
        if [[ -n "$PEERS_FILE" ]]; then
            cat "$PEERS_FILE"
        else
            cat << 'PEERS'
  - name: nodeA
    ed-pub: "48fd69d17c36d5391b7786f8091bce75e55f5b013344b60874090d53e8e8cdf7"
    pq-pub: "0966ee325a56afdd43318594bb66d891ea93d0adaf321866ab864cd3fcb3769d1a66eddabfe48c1660830791752780766cd33c520d852e1104584c9809e083677ea6dfab3289031484ceda174e5674b2e01a91a8e49f99bc34370e22b49453ebfb18bca8aae5a4e3c02a55a0df49f8d82b4a7a5c30bf6744b66cb5c807a6da8a7487609fdaf3441667585f04cf2864ac93f295a584bc70b2dda3870b80f40af40c62975a19883d92cea1d920119b1eb14c882bc7574f4a7f610871b544a094f2c0805fee6c8da6e9245a638067463463eb29e61f724e169ad56039a134e8c526bba6440dcb6b4ecf99e535bb91c4a6615d51c6cf515f997dfaca0ca3fd9311920157098dada08690169e1951353643f61cb95705961b7b5ff6955c8256fb58c7ad60650480d8dca445159816037d8c601baa12ecae0614197080c51db7380559994d237b01786a880fcd1730d8f19be87e5cd6f7b27c181d8516d256c825335f760b4430928b5bb8619b5740ec77498250da2624ad5d325518a4126bd538a8b862698a85b340bfaa33321c9990bfc08209487314be65ca916d8522a8272a7586538749e234570e4c58c2ac144adda1e4b440054bd4a852bfc731640687d92d878894de5fc82086b4ae202e01f957a5865a5f9a84697166695cdb5755e838612f54e919f1181a49a07c22cc1150d81ba3d9ef48954a2a2b55871f18cbd68c5d08446a861b96cf7f1fa073d1065e0000ad73656b9d41b9287064612c7027bcd011e061b0ab0a03aa72a5c5364ebdd41fa46e7ff11471aa4e761df92188cb84dc411c26e0218ee852be13523116e9a50ad0b8a4438b2cc185fb4ea7052f620715839ad600eda04569e58844bd1cbbca625e2dddabe36b2adeadd2158986ece050fc410b4c43625cb56bd5ce469d2b39d4d6aeca8d444893a35e64abbb14fc4456aa4c9ba8f390256ad275158f61bf4de608b202235347040a4dd1e7396ab692cc2ca8d3d8b3b74574a69de10c2d500d57d8eb86b3c5fa7229580bb292edc2e06c42b2203c9147d4cc658989b61b43ddbbb6ef7672af62a24c0ad38a1ad83f0db96724ea6220a228a06f987978a933985f4b26a3995601170c6483b00741232e8d0cf54ad753e78d73121caaf0a1844d1e2d9a4c91842cb6983b896b9802186be58e0eea0884d9168ad99ebf503a39b8ebf2090419cb14565552ad4b6b1480edbcd94677ef24a54c0a47cae21032b9b490bb4e2c1d267c0dd990a4541cadc99a19dcf3"
    endpoints: ["212.113.103.105:9410"]
    allow: ["*"]
  - name: nodeD
    ed-pub: "df3d10f3549f492fa829553f9f0a1fe4e6daaf7a74aa532b5411db6eca6d2ba4"
    pq-pub: "098e3c69a5ce9da59264ea77cbaa6d551a4cf83d2ee7328d9cd654c628556c132613af7d5b366391fa56464ea490cb87cc5d311e7294cb20fdbb119ee31b03c39b26bee514cbd749d07d41a9d1854c729c1144449b996535b18722ba7d39369236515e48ddd9d791efa9491c1d845da7608770c815aa2dd9889ccb26d3231ba901c5b2845e842119f987f068dc4f283a229d847d77b2fc93570b247c9c38fa219379062eb369106bdc95b073b15f5295b9b02769349560661a074809c9651ebe821b4cd9873bced8077623e3b07cc2199a29a8ba36a9ea10d78c4edcab73b9e9301f38fba7e3e9a30f4cd4e94242604ce8a2b12bebc00354dab36728340a1c2261ee856c211a9e1b01016ebf84c511b856c97054ee179ead4b9fe47367f6e1fa50a8aca31adbdd1a780a65b1a82b66deace8a345456cc2b71937e9de017d9e3899208d169a8020b0697f7b551a12b6c45bbfda0ee36f2fa922e20ca2a25f221298578754e003323c2d9135a435935a13a3cf62c93e3005e01ad57a6434ce7aa1d70c36ae3d630166978304d581dca2339198fcd527a9bb0878c1e0e200497300db65c8c1943bcac1b17b661f247a7676051a910baaf9b9744fd181ce78c49dad5c79ad2dd4c3e2d355fd6cb6846f63bb4aaeb3ff12218535a4f84bd9e611904a05712c51156239c861e1524b1d336471490b05a09359a42a65a8c5a599048d7ba0865e0649a32e62b55969054a6609a516dbad89ebbdc4f82835db7a9c093e13fa67812588cd68720c7466e10d31390ed2b26289db412d3baab479e7722114345ed4400191555e1ea1d5444a5bbf4969157095731d89393608ae6c99f6702a060ad918aab14b1fa9ec2a80e405f3147e843d78e7e05c8b5be29156036186791d4a7a9a8c0f861d3fa0009e170ad177b7142eb459b87714889006af8a4ec615050cbfe80a75c091fd80569a991dee9a219d24f81ac3c91c962946e89c4e5615c84a3f2f098cb4eb0895977c8a06335a7e19ef327ebd030b074f9848813806064453727ceb9bee3509a93a12c91142554455ba5a82949884d1a3e665b582100cb097544969a90df28f9f835cbcb9c8475fa149de8f2a540fbc21b5c943f283454b4d0d142ee9860d6627e9511c1d44a4f6f19b2ad07ac6e8164060df3100cbb91d92adb6518179301c612968aed5de26e3058e8cca42650c1cde1617700a4449c5747affedac15b61ed81aae8b557d1184a1eee9b3aacc05998b62ad127534124235"
    endpoints: ["138.124.102.200:9410"]
    allow: ["*"]
PEERS
        fi
    } > "$YAML_FILE"
    chmod 644 "$YAML_FILE"
    ok "wrote $YAML_FILE"
fi

# 3. Generate node.env (mode 0600, no hardcoded private keys or API tokens)
if [[ -f "$ENV_FILE" && "$FORCE" == "0" ]]; then
    log "$ENV_FILE already exists; keeping it (pass --force to regenerate)"
    if ! grep -q '^STELL_KEY_PASSPHRASE=' "$ENV_FILE"; then
        printf '\nSTELL_KEY_PASSPHRASE=%s\n' "$KEY_PASSPHRASE" >> "$ENV_FILE"
        chmod 600 "$ENV_FILE"
    fi
else
    if [[ -f "$ENV_FILE" ]]; then
        cp "$ENV_FILE" "$ENV_FILE.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    cat > "$ENV_FILE" << EOF
# Stellereum node environment generated by scripts/join-testnet.sh
# Start as observer while syncing from snapshot; validators flip STELL_OBSERVER=0
# only after registering on-chain and entering the active set.
STELL_OBSERVER=1
STELL_SHARDS=0
STELL_CHAIN_ID=$CHAIN_ID
STELL_RPC_LISTEN=$RPC
STELL_EXPLORER_LISTEN=$EXPLORER
STELL_ARCHIVE=0
STELL_KEEP_BLOCKS=8000
STELL_DNS_SEEDS=$SEEDS
STELL_BROADCAST_JOIN_MS=300
STELL_KEY_PASSPHRASE=$KEY_PASSPHRASE
EOF
    chmod 600 "$ENV_FILE"
    ok "wrote $ENV_FILE (0600)"
fi

# 4. Bootstrap snapshot into data/store
if [[ "$SKIP_SNAPSHOT" == "1" ]]; then
    warn "skipping snapshot download (--skip-snapshot)"
elif [[ -d "$HOME_DIR/data/store" && "$REFRESH_STORE" == "0" ]]; then
    log "existing store found at $HOME_DIR/data/store; skipping snapshot download (pass --refresh-store to replace)"
else
    BOOTSTRAP_SCRIPT="$ROOT_DIR/scripts/auto-bootstrap-store.sh"
    [[ -f "$BOOTSTRAP_SCRIPT" ]] || die "missing helper script: $BOOTSTRAP_SCRIPT"
    bootstrap_args=(
        --home "$HOME_DIR"
        --snapshot-url "$SNAPSHOT_URL"
        --binary "$BINARY"
        --keys-dir "$HOME_DIR/keys"
        --shard 0
        --env-file "$ENV_FILE"
    )
    if [[ "$SHA256_URL_SET" == "1" ]]; then
        bootstrap_args+=(--sha256-url "$SHA256_URL")
    fi
    if [[ "$REQUIRE_SHA256" == "1" ]]; then
        bootstrap_args+=(--require-sha256)
    fi
    if [[ "$REFRESH_STORE" == "1" ]]; then
        bootstrap_args+=(--refresh-if-stale)
    fi
    bash "$BOOTSTRAP_SCRIPT" "${bootstrap_args[@]}"
    ok "snapshot extracted to $HOME_DIR/data/store (safety record initialised for this node)"
fi

printf '\n================ NEXT STEPS (%s) ================\n' "$MODE"
if [[ "$MODE" == "observer" ]]; then
    cat << EOF
1. Start your observer node:
     cd "$HOME_DIR"
     set -a; source node.env; set +a
     "$BINARY" run --config node.yaml --shard 0 --parallel-exec

2. Verify sync & state root against the live testnet:
     curl -s -X POST "http://$RPC" -H "content-type: application/json" \\
       -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}'
     curl -s -X POST "http://$RPC" -H "content-type: application/json" \\
       -d '{"jsonrpc":"2.0","id":1,"method":"stell_syncing","params":[]}'

3. Security: back up $HOME_DIR/keys/ and $HOME_DIR/node.env together (0600).
EOF
else
    cat << EOF
Generated keys in $HOME_DIR/keys/ (0700 dir, 0600 encrypted files):
  - Hot voting key:       $HOME_DIR/keys/falcon.key
  - Cold withdrawal key:  $HOME_DIR/keys/withdrawal.key
  - Node transport/BFT:   $HOME_DIR/keys/pq-identity.key, e2e.key, validator.key
  - Peer stanza:          $HOME_DIR/peer-stanza.txt
EOF
    if [[ -n "$WITHDRAWAL_ADDRESS" ]]; then
        printf '  - Withdrawal address:   %s (masterchain: -1:%s)\n' "$WITHDRAWAL_ADDRESS" "$WITHDRAWAL_ADDRESS"
    fi
    if [[ -n "$VALIDATOR_ID" ]]; then
        printf '  - Validator ID:         %s\n' "$VALIDATOR_ID"
    fi
    cat << EOF

1. BACK UP $HOME_DIR/keys/ AND $HOME_DIR/node.env (contains STELL_KEY_PASSPHRASE)
   before funding any tokens. Move withdrawal.key to cold/offline storage after
   registering; only falcon.key stays hot on the validator host.

2. Ensure UDP $P2P_PORT is open inbound (QUIC P2P), then start the node to sync
   from the snapshot to the live tip (starts with STELL_OBSERVER=1):
     cd "$HOME_DIR"
     set -a; source node.env; set +a
     "$BINARY" run --config node.yaml --shard 0 --parallel-exec

3. Wait until your node finishes catching up (stell_syncing == false), then fund
   the cold withdrawal address with >= 1,100 STELL (1,000 STELL minimum bond +
   100 STELL admission buffer, plus a small gas margin, e.g. 1,101 STELL) on
   shard 0 (masterchain: -1:<withdrawal_address>).
   The public faucet is capped at 50 STELL (2 STELL per drip, 45-minute
   cooldown) and CANNOT fund this bond. Validator stake comes from the
   Foundation on request or an operator transfer.

4. Register your validator on-chain (OpCode 59, Falcon-512 PoP):
     set -a; source "$HOME_DIR/node.env"; set +a
     "$BINARY" validator register-validator \\
       --withdrawal-key-file "$HOME_DIR/keys/withdrawal.key" \\
       --voting-key-file "$HOME_DIR/keys/falcon.key" \\
       --amount 1100000000000 \\
       --commission-bps "$COMMISSION_BPS" \\
       --rpc "http://$RPC"

5. Confirm your validator appears in stell_stakeOf and stell_getValidators, then
   promote the node from observer to validator:
     sed -i 's/^STELL_OBSERVER=1$/STELL_OBSERVER=0/' "$HOME_DIR/node.env"
   and restart the node.
EOF
fi

if [[ "$START_NOW" == "1" ]]; then
    log "starting node in $HOME_DIR..."
    cd "$HOME_DIR"
    set -a
    # shellcheck disable=SC1091
    source "$ENV_FILE"
    set +a
    exec "$BINARY" run --config node.yaml --shard 0 --parallel-exec
fi
