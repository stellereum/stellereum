#!/usr/bin/env bash
# ==============================================================================
# Stellereum Observer / Full Node Runner
# Anyone can run this node to verify blocks, transactions, and state roots
# without staking any tokens.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

REQUIRE_SHA256="${STELL_REQUIRE_SHA256:-1}"
REQUIRE_COSIGN="${STELL_REQUIRE_COSIGN:-0}"
SNAPSHOT_URL="${STELL_SNAPSHOT_URL:-https://rpc.stellereum.org/snapshot/latest.tar.zst}"
SHA256_URL=""
SHA256_URL_SET=0
COSIGN_SIG_URL=""
COSIGN_SIG_URL_SET=0
COSIGN_PEM_URL=""
COSIGN_PEM_URL_SET=0
FORCE_ENV=0
NODE_DIR=""

usage() {
    cat <<EOF
Usage: $0 [NODE_DIR] [OPTIONS]

Options:
  --snapshot-url URL          Snapshot archive URL (default: \$STELL_SNAPSHOT_URL)
  --sha256-url URL            Snapshot SHA-256 checksum URL
  --require-sha256            Require SHA-256 verification (default)
  --allow-unverified-snapshot Allow missing SHA-256 manifest
  --cosign, --require-cosign  Verify snapshot with cosign via verify-cosign-artifact.sh
  --cosign-sig-url URL        Override cosign .sig URL
  --cosign-pem-url URL        Override cosign .pem URL
  --force-env                 Overwrite existing env.observer tuning (creates backup)
  -h, --help                  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --snapshot-url) SNAPSHOT_URL="${2:?--snapshot-url requires a URL}"; shift 2 ;;
        --snapshot-url=*) SNAPSHOT_URL="${1#--snapshot-url=}"; shift ;;
        --sha256-url) SHA256_URL="${2:?--sha256-url requires a URL}"; SHA256_URL_SET=1; shift 2 ;;
        --sha256-url=*) SHA256_URL="${1#--sha256-url=}"; SHA256_URL_SET=1; shift ;;
        --require-sha256) REQUIRE_SHA256=1; shift ;;
        --allow-unverified-snapshot) REQUIRE_SHA256=0; shift ;;
        --cosign|--require-cosign) REQUIRE_COSIGN=1; shift ;;
        --cosign-sig-url) COSIGN_SIG_URL="${2:?--cosign-sig-url requires a URL}"; COSIGN_SIG_URL_SET=1; shift 2 ;;
        --cosign-sig-url=*) COSIGN_SIG_URL="${1#--cosign-sig-url=}"; COSIGN_SIG_URL_SET=1; shift ;;
        --cosign-pem-url) COSIGN_PEM_URL="${2:?--cosign-pem-url requires a URL}"; COSIGN_PEM_URL_SET=1; shift 2 ;;
        --cosign-pem-url=*) COSIGN_PEM_URL="${1#--cosign-pem-url=}"; COSIGN_PEM_URL_SET=1; shift ;;
        --force-env) FORCE_ENV=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) echo "Unknown flag: $1" >&2; exit 2 ;;
        *)
            if [[ -z "$NODE_DIR" ]]; then
                NODE_DIR="$1"
            else
                echo "Unexpected argument: $1" >&2
                exit 2
            fi
            shift
            ;;
    esac
done
NODE_DIR="${NODE_DIR:-$HOME/stell-observer}"
BIN_PATH="${STELL_BIN:-}"

case "$REQUIRE_COSIGN" in
    0|1) ;;
    *) echo -e "\033[1;31m[ERROR]\033[0m STELL_REQUIRE_COSIGN must be 0 or 1 (got '$REQUIRE_COSIGN')" >&2; exit 2 ;;
esac
if [[ "$COSIGN_SIG_URL_SET" == "1" && -z "$COSIGN_SIG_URL" ]]; then
    echo -e "\033[1;31m[ERROR]\033[0m --cosign-sig-url cannot be empty" >&2; exit 2
fi
if [[ "$COSIGN_PEM_URL_SET" == "1" && -z "$COSIGN_PEM_URL" ]]; then
    echo -e "\033[1;31m[ERROR]\033[0m --cosign-pem-url cannot be empty" >&2; exit 2
fi
if [[ "$COSIGN_SIG_URL_SET" == "1" && "$COSIGN_PEM_URL_SET" == "0" ]]; then
    if [[ "$REQUIRE_COSIGN" == "1" ]]; then
        COSIGN_PEM_URL="${SNAPSHOT_URL}.pem"
    else
        echo -e "\033[1;31m[ERROR]\033[0m --cosign-sig-url requires --cosign-pem-url" >&2; exit 2
    fi
fi
if [[ "$COSIGN_PEM_URL_SET" == "1" && "$COSIGN_SIG_URL_SET" == "0" ]]; then
    if [[ "$REQUIRE_COSIGN" == "1" ]]; then
        COSIGN_SIG_URL="${SNAPSHOT_URL}.sig"
    else
        echo -e "\033[1;31m[ERROR]\033[0m --cosign-pem-url requires --cosign-sig-url" >&2; exit 2
    fi
fi
USE_COSIGN=0
if [[ "$REQUIRE_COSIGN" == "1" || ( -n "$COSIGN_SIG_URL" && -n "$COSIGN_PEM_URL" ) ]]; then
    USE_COSIGN=1
    [[ -n "$COSIGN_SIG_URL" ]] || COSIGN_SIG_URL="${SNAPSHOT_URL}.sig"
    [[ -n "$COSIGN_PEM_URL" ]] || COSIGN_PEM_URL="${SNAPSHOT_URL}.pem"
fi

if [[ -z "$BIN_PATH" ]]; then
    for cand in \
        "$ROOT_DIR/target/release/stellereum" \
        "$ROOT_DIR/stellereum/target/release/stellereum" \
        "$ROOT_DIR/target/debug/stellereum" \
        "$ROOT_DIR/stellereum/target/debug/stellereum" \
        "$(command -v stellereum 2>/dev/null || true)"; do
        if [[ -n "$cand" && -x "$cand" ]]; then
            BIN_PATH="$cand"
            break
        fi
    done
fi

if [[ -z "$BIN_PATH" || ! -x "$BIN_PATH" ]]; then
    echo -e "\033[1;31m[ERROR]\033[0m stellereum binary not found. Build it with 'cargo build --release' from repo root first." >&2
    exit 1
fi

echo -e "\033[1;34m[stell-observer]\033[0m Setting up Observer Node in $NODE_DIR..."
mkdir -p "$NODE_DIR/data" "$NODE_DIR/keys"
chmod 700 "$NODE_DIR/data" "$NODE_DIR/keys"

# Generate observer configuration if not already provided
if [[ ! -f "$NODE_DIR/observer.yaml" ]]; then
    if [[ -n "${STELL_OBSERVER_PEERS_FILE:-}" ]]; then
        if [[ ! -f "$STELL_OBSERVER_PEERS_FILE" ]]; then
            echo -e "\033[1;31m[ERROR]\033[0m STELL_OBSERVER_PEERS_FILE '$STELL_OBSERVER_PEERS_FILE' not found." >&2
            exit 1
        fi
        {
            echo "name: observer"
            echo 'listen: "0.0.0.0:9411"'
            echo "storage-roles:"
            echo "  - mail"
            echo "  - files"
            echo "log-level: 2"
            echo "allow-unknown: true"
            echo "unknown-allow:"
            echo '  - "dht.lookup"'
            echo '  - "dht.update"'
            echo '  - "dht.find_node"'
            echo '  - "dht.find_value"'
            echo "validators: []"
            echo "peers:"
            cat "$STELL_OBSERVER_PEERS_FILE"
        } > "$NODE_DIR/observer.yaml"
    else
        cat << 'YAML' > "$NODE_DIR/observer.yaml"
name: observer
listen: "0.0.0.0:9411"
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
YAML
    fi
fi

# Preserve or mint node keystore passphrase (required for encrypted-at-rest keys)
KEY_PASSPHRASE=""
if [[ -f "$NODE_DIR/env.observer" ]]; then
    KEY_PASSPHRASE="$(sed -n 's/^STELL_KEY_PASSPHRASE=//p' "$NODE_DIR/env.observer" | head -1)"
fi
if [[ -z "$KEY_PASSPHRASE" && -n "${STELL_KEY_PASSPHRASE:-}" ]]; then
    KEY_PASSPHRASE="$STELL_KEY_PASSPHRASE"
fi
if [[ -z "$KEY_PASSPHRASE" ]]; then
    KEY_PASSPHRASE="$(head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '/+' '_-')"
fi

# Preserve existing env.observer tuning unless --force-env is given
if [[ -f "$NODE_DIR/env.observer" && "$FORCE_ENV" == "0" ]]; then
    echo -e "\033[1;34m[stell-observer]\033[0m Preserving existing $NODE_DIR/env.observer (pass --force-env to overwrite)"
    if ! grep -q '^STELL_KEY_PASSPHRASE=' "$NODE_DIR/env.observer"; then
        printf '\nSTELL_KEY_PASSPHRASE=%s\n' "$KEY_PASSPHRASE" >> "$NODE_DIR/env.observer"
    fi
    chmod 600 "$NODE_DIR/env.observer"
else
    if [[ -f "$NODE_DIR/env.observer" ]]; then
        cp "$NODE_DIR/env.observer" "$NODE_DIR/env.observer.bak.$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    # Environment for Observer (no faucet key, single-shard masterchain 0)
    cat << EOF > "$NODE_DIR/env.observer"
STELL_OBSERVER=1
STELL_RPC_LISTEN=${STELL_RPC_LISTEN:-127.0.0.1:8547}
STELL_EXPLORER_LISTEN=${STELL_EXPLORER_LISTEN:-127.0.0.1:8082}
STELL_ARCHIVE=0
STELL_KEEP_BLOCKS=8000
STELL_MIN_BLOCK_MS=${STELL_MIN_BLOCK_MS:-400}
STELL_SHARDS=0
STELL_DNS_SEEDS=seeds.stellereum.org
STELL_BROADCAST_JOIN_MS=300
STELL_KEY_PASSPHRASE=$KEY_PASSPHRASE
EOF
    chmod 600 "$NODE_DIR/env.observer"
fi

# Guard against running observer safety-reset on a validator node directory
env_observer_val="${STELL_OBSERVER:-}"
if [[ -z "$env_observer_val" && -f "$NODE_DIR/env.observer" ]]; then
    env_observer_val="$(sed -n 's/^[[:space:]]*STELL_OBSERVER=//p' "$NODE_DIR/env.observer" | tail -n 1 | tr -d "\"'[:space:]")"
fi
if [[ -e "$NODE_DIR/keys/validator.key" ]]; then
    echo -e "\033[1;31m[ERROR]\033[0m Refusing observer bootstrap/safety-reset: $NODE_DIR/keys/validator.key exists (validator directory!)" >&2
    exit 1
fi
if [[ "$env_observer_val" == "0" || "$env_observer_val" == "false" ]]; then
    echo -e "\033[1;31m[ERROR]\033[0m Refusing observer bootstrap/safety-reset: STELL_OBSERVER=$env_observer_val" >&2
    exit 1
fi

if [[ ! -d "$NODE_DIR/data/store" ]]; then
    echo -e "\033[1;34m[stell-observer]\033[0m Initializing state from live HTTP snapshot..."
    snap_url="$SNAPSHOT_URL"
    COSIGN_WORK_DIR=""
    cleanup_cosign_work() {
        if [[ -n "$COSIGN_WORK_DIR" && -d "$COSIGN_WORK_DIR" ]]; then
            rm -rf "$COSIGN_WORK_DIR"
        fi
    }
    trap cleanup_cosign_work EXIT

    bootstrap_args=(
        store bootstrap
        --observer
        --data-dir "$NODE_DIR/data"
        --shard 0
        --snapshot-url "$snap_url"
    )
    if [[ "$USE_COSIGN" == "1" ]]; then
        COSIGN_VERIFIER="$SCRIPT_DIR/verify-cosign-artifact.sh"
        if [[ ! -x "$COSIGN_VERIFIER" ]]; then
            echo -e "\033[1;31m[ERROR]\033[0m Cosign verifier script missing or not executable: $COSIGN_VERIFIER" >&2
            exit 1
        fi
        for tool in curl cosign; do
            if ! command -v "$tool" >/dev/null 2>&1; then
                echo -e "\033[1;31m[ERROR]\033[0m Required tool '$tool' not found in PATH for --cosign" >&2
                exit 1
            fi
        done

        COSIGN_WORK_DIR="$(mktemp -d)"
        archive_file="$COSIGN_WORK_DIR/snapshot.tar.zst"
        sig_file="$COSIGN_WORK_DIR/snapshot.tar.zst.sig"
        pem_file="$COSIGN_WORK_DIR/snapshot.tar.zst.pem"

        echo -e "\033[1;34m[stell-observer]\033[0m Downloading snapshot and cosign bundle for verification..."
        curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$archive_file" "$snap_url"
        curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$sig_file" "$COSIGN_SIG_URL"
        curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$pem_file" "$COSIGN_PEM_URL"
        "$COSIGN_VERIFIER" --require --sig "$sig_file" --pem "$pem_file" "$archive_file"
        echo -e "\033[1;32m[OK]\033[0m Snapshot cosign signature verified"

        bootstrap_args+=(--archive "$archive_file")
        if [[ "$SHA256_URL_SET" == "1" ]]; then
            bootstrap_args+=(--sha256-url "$SHA256_URL")
        else
            bootstrap_args+=(--sha256-url "${snap_url}.sha256")
        fi
    elif [[ "$SHA256_URL_SET" == "1" ]]; then
        bootstrap_args+=(--sha256-url "$SHA256_URL")
    fi
    if [[ "$REQUIRE_SHA256" = "1" ]]; then
        bootstrap_args+=(--require-sha256)
    fi
    "$BIN_PATH" "${bootstrap_args[@]}"
    cleanup_cosign_work
    if [[ ! -d "$NODE_DIR/data/store" ]]; then
        echo -e "\033[1;31m[ERROR]\033[0m Snapshot bootstrap did not populate $NODE_DIR/data/store" >&2
        exit 1
    fi
else
    # Ensure a pre-existing observer store never carries a foreign safety_record_v1
    if ! "$BIN_PATH" safety-reset --store-dir "$NODE_DIR/data/store" --i-fenced-all-signers; then
        echo -e "\033[1;31m[ERROR]\033[0m safety-reset failed on $NODE_DIR/data/store" >&2
        exit 1
    fi
fi

echo -e "\033[1;32m[OK]\033[0m Observer configuration ready!"

cd "$NODE_DIR"
set -a
# shellcheck disable=SC1091
source env.observer
set +a
echo -e "\033[1;34m[stell-observer]\033[0m Starting Observer node (RPC at ${STELL_RPC_LISTEN:-127.0.0.1:8547})..."
exec "$BIN_PATH" run --config observer.yaml --shard 0 --parallel-exec
