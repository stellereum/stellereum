# Stellereum node — multi-stage build.
#   docker build -t stellereum/node .
#   docker run -p 9410:9410/udp -p 8545:8545 stellereum/node
#
# The build context MUST include both the blockchain and its infnode dependency,
# so build from the parent directory that contains both, e.g.:
#   docker build -f stellereum/Dockerfile -t stellereum/node .
# or use the provided docker-compose.

# ---------- builder ----------
FROM rust:1.95-slim AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy the infnode workspace (network layer) and the blockchain.
COPY infmail-valid-backend /build/infmail-valid-backend
COPY stellereum /build/stellereum

# Point the blockchain at the in-image infnode path (overrides the local one).
RUN sed -i 's#path = ".*crates/infnode"#path = "/build/infmail-valid-backend/crates/infnode"#' \
        /build/stellereum/Cargo.toml

WORKDIR /build/stellereum
RUN cargo build --release --bin stellereum

# ---------- runtime ----------
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/stellereum
COPY --from=builder /build/stellereum/target/release/stellereum /usr/local/bin/stellereum
COPY stellereum/docker/node.yaml /opt/stellereum/node.yaml

# QUIC (P2P) + JSON-RPC + Explorer/Gateway
EXPOSE 9410/udp
EXPOSE 8545/tcp
EXPOSE 8080/tcp

VOLUME ["/opt/stellereum/data", "/opt/stellereum/keys"]

# SECURITY: world binds with NO auth tokens (fail-open dev defaults). For any
# non-localhost use, set STELL_RPC_AUTH_TOKEN (+ STELL_FAUCET_TOKEN) or bind
# loopback — the node warns loudly on open binds without tokens. See compose.
ENV STELL_RPC_LISTEN=0.0.0.0:8545
ENV STELL_EXPLORER_LISTEN=0.0.0.0:8080

ENTRYPOINT ["stellereum"]
CMD ["run", "--config", "/opt/stellereum/node.yaml", "--shard", "1"]
