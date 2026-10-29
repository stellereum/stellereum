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

# Generate observer configuration
cat << 'YAML' > "$NODE_DIR/observer.yaml"
name: observer
listen: "0.0.0.0:9411"
validators: []
peers:
  - name: nodeA
    node-id: "inf1:56d7b3a5570626a6822b992041367bb7e2b7298a"
    ed-pub: "c2313fbaf5c0b1a4921f132bed48772f0d0b788b8f27ad7f96772610996c3361"
    x-pub: "04fe590d752cecec371dd3f98943ca241ad0e6f741db5e7feb20326ec899fc7c"
    endpoints: ["212.113.103.105:9410"]
    allow: ["*"]
  - name: nodeC
    node-id: "inf1:ba7f458a343b41706c4a26754db0a4f935cf58ed"
    ed-pub: "021776cdf2b3b644e91dbe44fbef4a29f5a8ebf80b01055d3e7cc83a85659694"
    x-pub: "96a844dfcba2a2028fbcfc33498e6a1874b0f7d7eadd164e3237f8a7f0cb9878"
    endpoints: ["77.110.96.68:9410"]
    allow: ["*"]
  - name: nodeD
    node-id: "inf1:2a74bfe487f2b5e4f1e9913bc99d90d42b6e2e45"
    ed-pub: "eddf81632831d8e9747dc38edbb2c88a835e246a0310d74c8b12b8df6e32e4cc"
    x-pub: "cd38330338732ba62d3228bd0e02326c85f400dee53b530a898d97338b81e42a"
    endpoints: ["138.124.102.200:9410"]
    allow: ["*"]
YAML

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
