# infnode

> Testnet software — no real funds, no mainnet yet, no external audit yet.

Post-quantum QUIC+DHT transport layer for the Stellereum L1: peer auth,
reputation with bans, backpressure caps, ML-KEM session keys, Falcon-512
handshake. Used as a dependency by the node.

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange" alt="License"/></a>
</p>

## Layout

```text
crates/infnode/   the transport: QUIC endpoints, DHT, pubsub, reputation, caps
```

Sibling directories (`crates/infmail/`, `contracts/`, `nft/`, `tools-src/`)
are experimental overlays, not part of the transport — ignore them unless
you work on mail tooling.

## Build & test

```bash
cargo build -p infnode
cargo test -p infnode
cargo clippy -p infnode --all-targets -- -D warnings
```

## Security

No external audit yet. Testnet only. **Never open a public issue for a
suspected vulnerability** — report via [`SECURITY.md`](SECURITY.md).

## Contributing · License

Keep `cargo test` green and clippy clean. MIT **or** Apache-2.0
([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).
