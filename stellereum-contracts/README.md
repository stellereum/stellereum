# stellereum-contracts

> Testnet software — no real funds, no mainnet yet, no external audit yet.

Smart contracts and on-chain programs for the Stellereum L1: STS-20 tokens,
DNS names, liquidity pools, account objects. Audited in-tree (auth, validation,
overflow, economic-abuse batteries); external audit pending.

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange" alt="License"/></a>
</p>

## Layout

```text
contracts/sts20-token      fungible tokens (allowance, dust guards)
contracts/stl-dns          on-chain names (strict auction state machine)
contracts/liquidity-pool   AMM pools (exact share math, overflow-closed)
contracts/account-object   sessions with budgets and tombstones
crates/stellereum-contract-sdk   host bindings (auth, storage, crypto)
crates/e2e-tests           end-to-end + adversarial suites
```

## Build & test

```bash
cargo test                # default members (unit + harness suites)
cargo test -p e2e-tests   # end-to-end against an L1 build
cargo clippy --all-targets -- -D warnings
```

## Security

No external audit yet. Testnet only. **Never open a public issue for a
suspected vulnerability** — report via [`SECURITY.md`](SECURITY.md).

## Contributing · License

Keep tests green, no weakening to pass. MIT **or** Apache-2.0
([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).
