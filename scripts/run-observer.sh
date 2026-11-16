#!/usr/bin/env bash
# ==============================================================================
# Stellereum Observer / Full Node Runner
# Anyone can run this node to verify blocks, transactions, and state roots
# without staking any tokens.
# ==============================================================================
set -eo pipefail

NODE_DIR="${1:-$HOME/stell-observer}"
BIN_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/stellereum/target/release/stellereum"

if [[ ! -f "$BIN_PATH" ]]; then
    BIN_PATH="$(which stellereum 2>/dev/null || true)"
fi

if [[ -z "$BIN_PATH" || ! -f "$BIN_PATH" ]]; then
    echo -e "\033[1;31m[ERROR]\033[0m stellereum binary not found. Build it with 'cargo build --release' first."
    exit 1
fi

echo -e "\033[1;34m[stell-observer]\033[0m Setting up Observer Node in $NODE_DIR..."
mkdir -p "$NODE_DIR/data"

# Generate observer configuration if not already provided
if [[ ! -f "$NODE_DIR/observer.yaml" ]]; then
    if [[ -n "${STELL_OBSERVER_PEERS_FILE:-}" && -f "$STELL_OBSERVER_PEERS_FILE" ]]; then
        {
            echo "name: observer"
            echo 'listen: "0.0.0.0:9411"'
            echo "validators: []"
            echo "peers:"
            cat "$STELL_OBSERVER_PEERS_FILE"
        } > "$NODE_DIR/observer.yaml"
    else
        cat << 'YAML' > "$NODE_DIR/observer.yaml"
name: observer
listen: "0.0.0.0:9411"
validators: []
# FULL-PQ: populate `ed-pub` + 897-byte `pq-pub` from `stellereum keys peer-stanza`
# on your bootstrap validator(s). Legacy `node-id:` / `x-pub:` fields are rejected.
peers:
  - name: nodeA
    ed-pub: "c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361"
    pq-pub: "<REPLACE_WITH_897_BYTE_FALCON512_PUBKEY_HEX>"
    endpoints: ["212.113.103.105:9410"]
    allow: ["*"]
YAML
    fi
fi

if grep -q '<REPLACE_WITH_897_BYTE_FALCON512_PUBKEY_HEX>' "$NODE_DIR/observer.yaml"; then
    echo -e "\033[1;31m[ERROR]\033[0m $NODE_DIR/observer.yaml still has placeholder pq-pub." >&2
    echo "        Replace it using 'stellereum keys peer-stanza' output or pass STELL_OBSERVER_PEERS_FILE=/path/to/peers.yaml" >&2
    exit 1
fi

# Environment for Observer
cat << 'ENV' > "$NODE_DIR/env.observer"
STELL_OBSERVER=1
STELL_FAUCET_KEY=1111111111111111111111111111111111111111111111111111111111111111
STELL_RPC_LISTEN=127.0.0.1:8547
STELL_EXPLORER_LISTEN=127.0.0.1:8082
STELL_ARCHIVE=0
STELL_KEEP_BLOCKS=8000
STELL_SHARDS=0,1
STELL_PURE_PQ=1
STELL_LEGACY_GENESIS_ROOT=1
STELL_DNS_SEEDS=seeds.stellereum.org
STELL_BROADCAST_JOIN_MS=300
ENV

if [[ ! -d "$NODE_DIR/data/store" ]]; then
    echo -e "\033[1;34m[stell-observer]\033[0m Initializing state from live HTTP snapshot..."
    curl -sL "https://rpc.stellereum.org/snapshot/latest.tar.zst" | tar -I 'zstd -d' -xf - -C "$NODE_DIR/data/"
    rm -f "$NODE_DIR/data/store"/snap* "$NODE_DIR/data/store-shard"*"/snap"* 2>/dev/null || true
fi

echo -e "\033[1;32m[OK]\033[0m Observer configuration ready!"
echo -e "\033[1;34m[stell-observer]\033[0m Starting Observer node (RPC at 127.0.0.1:8547)..."

cd "$NODE_DIR"
set -a
source env.observer
set +a
exec "$BIN_PATH" run --config observer.yaml --shard 0 --parallel-exec
