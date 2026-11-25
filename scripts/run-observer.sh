#!/usr/bin/env bash
# ==============================================================================
# Stellereum Observer / Full Node Runner
# Anyone can run this node to verify blocks, transactions, and state roots
# without staking any tokens.
# ==============================================================================
set -euo pipefail

REQUIRE_SHA256="${STELL_REQUIRE_SHA256:-0}"
NODE_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --require-sha256) REQUIRE_SHA256=1; shift ;;
        -h|--help) echo "Usage: $0 [NODE_DIR] [--require-sha256]"; exit 0 ;;
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
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="${STELL_BIN:-}"

if [[ -z "$BIN_PATH" ]]; then
    for cand in \
        "$ROOT_DIR/target/release/stellereum" \
        "$ROOT_DIR/target/debug/stellereum" \
        "$ROOT_DIR/stellereum/target/release/stellereum" \
        "$ROOT_DIR/stellereum/target/debug/stellereum" \
        "$(command -v stellereum 2>/dev/null || true)"; do
        if [[ -n "$cand" && -x "$cand" ]]; then
            BIN_PATH="$cand"
            break
        fi
    done
fi

if [[ -z "$BIN_PATH" || ! -x "$BIN_PATH" ]]; then
    echo -e "\033[1;31m[ERROR]\033[0m stellereum binary not found. Build it with 'cargo build --release' in stellereum/ first." >&2
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

# Environment for Observer (no faucet key, single-shard masterchain 0)
cat << EOF > "$NODE_DIR/env.observer"
STELL_OBSERVER=1
STELL_RPC_LISTEN=${STELL_RPC_LISTEN:-127.0.0.1:8547}
STELL_EXPLORER_LISTEN=${STELL_EXPLORER_LISTEN:-127.0.0.1:8082}
STELL_ARCHIVE=0
STELL_KEEP_BLOCKS=8000
STELL_SHARDS=0
STELL_DNS_SEEDS=seeds.stellereum.org
STELL_BROADCAST_JOIN_MS=300
STELL_KEY_PASSPHRASE=$KEY_PASSPHRASE
EOF
chmod 600 "$NODE_DIR/env.observer"

if [[ ! -d "$NODE_DIR/data/store" ]]; then
    echo -e "\033[1;34m[stell-observer]\033[0m Initializing state from live HTTP snapshot..."
    snap_url="${STELL_SNAPSHOT_URL:-https://rpc.stellereum.org/snapshot/latest.tar.zst}"
    snap_tmp="$(mktemp "$NODE_DIR/data/.snapshot.XXXXXX.tar.zst")"
    cleanup_snap() { rm -f "$snap_tmp"; }
    trap cleanup_snap EXIT

    if ! curl -fsSL "$snap_url" -o "$snap_tmp"; then
        echo -e "\033[1;31m[ERROR]\033[0m Failed to download snapshot from $snap_url" >&2
        exit 1
    fi
    if ! zstd -t "$snap_tmp"; then
        echo -e "\033[1;31m[ERROR]\033[0m Snapshot archive failed zstd integrity check" >&2
        exit 1
    fi
    sha_body="$(curl -fsSL "${snap_url}.sha256" 2>/dev/null || true)"
    if [[ -n "$sha_body" ]]; then
        expected_sha="$(printf '%s\n' "$sha_body" | awk 'NR==1 {print tolower($1)}')"
        if [[ ! "$expected_sha" =~ ^[0-9a-f]{64}$ ]]; then
            echo -e "\033[1;31m[ERROR]\033[0m Malformed .sha256 manifest from ${snap_url}.sha256" >&2
            exit 1
        fi
        actual_sha="$(sha256sum "$snap_tmp" | awk '{print tolower($1)}')"
        if [[ "$actual_sha" != "$expected_sha" ]]; then
            echo -e "\033[1;31m[ERROR]\033[0m Snapshot sha256 mismatch: expected=$expected_sha actual=$actual_sha" >&2
            exit 1
        fi
        echo -e "\033[1;32m[OK]\033[0m Verified snapshot sha256 ($actual_sha)"
    elif [[ "$REQUIRE_SHA256" = "1" ]]; then
        echo -e "\033[1;31m[ERROR]\033[0m --require-sha256 set, but ${snap_url}.sha256 is unavailable" >&2
        exit 1
    else
        echo -e "\033[1;33m[WARN]\033[0m ${snap_url}.sha256 unavailable; continuing after zstd -t check" >&2
    fi

    tar -I 'zstd -d' -xf "$snap_tmp" -C "$NODE_DIR/data/"
    rm -f "$snap_tmp"
    trap - EXIT
    rm -f "$NODE_DIR/data/store"/snap* "$NODE_DIR/data/store-shard"*"/snap"* 2>/dev/null || true
    if [[ ! -d "$NODE_DIR/data/store" ]]; then
        echo -e "\033[1;31m[ERROR]\033[0m Snapshot extraction did not populate $NODE_DIR/data/store" >&2
        exit 1
    fi
fi

echo -e "\033[1;32m[OK]\033[0m Observer configuration ready!"
echo -e "\033[1;34m[stell-observer]\033[0m Starting Observer node (RPC at ${STELL_RPC_LISTEN:-127.0.0.1:8547})..."

cd "$NODE_DIR"
set -a
# shellcheck disable=SC1091
source env.observer
set +a
exec "$BIN_PATH" run --config observer.yaml --shard 0 --parallel-exec
