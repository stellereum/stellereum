# stellereum-sdk

> Testnet software — no real funds, no mainnet yet, no external audit yet.

Minimal canonical transaction-builder SDK for Stellereum: transfers, tokens,
staking, contract deploy and calls. Every byte comes from the node's own
constructors, so SDK output matches consensus encoding by construction.
Full reference: [`SDK-README.md`](SDK-README.md).

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange" alt="License"/></a>
</p>

## Install

```toml
[dependencies]
stellereum-sdk = { git = "https://github.com/stellereum/stellereum-sdk" }
```

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
