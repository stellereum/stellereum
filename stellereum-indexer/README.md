# stellereum-indexer

> Testnet software — no real funds, no mainnet yet, no external audit yet.

High-performance Rust indexer for the Stellereum L1: chain data into a
queryable REST API over SQLite WAL. See `src/` for the implementation and
`tests/` for the API test-suite.

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange" alt="License"/></a>
</p>

## Build & test

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

## Security

No external audit yet. Testnet only. **Never open a public issue for a
suspected vulnerability** — report via [`SECURITY.md`](SECURITY.md).

## Contributing · License

Keep tests green. MIT **or** Apache-2.0
([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).
