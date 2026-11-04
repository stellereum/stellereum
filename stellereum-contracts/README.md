# stellereum-contracts

> Testnet software — no real funds, no mainnet yet, no external audit yet.

Smart contracts and on-chain programs for the Stellereum L1: STS-20 tokens,
DNS names, liquidity pools, account objects. Audited in-tree (auth, validation,
overflow, economic-abuse batteries); external audit pending.

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange" alt="License"/></a>
</p>

## Programs

- **STS-20 tokens** (`contracts/sts20-token`) — allowances with front-run-safe
  overwrite semantics, dust-transfer refusal, overflow-closed arithmetic
- **DNS names** (`contracts/stl-dns`) — strict auction↔registered state machine,
  anti-snipe bid steps, no-lock transfers (owner-zero refused)
- **Liquidity pools** (`contracts/liquidity-pool`) — exact pro-rata share math,
  sandwich- and inflation-resistant deposits, overflow-closed swaps
- **Account objects** (`contracts/account-object`) — sessions with budgets,
  exact-drain boundaries, tombstoned revocation
- **Contract SDK** (`crates/stellereum-contract-sdk`) — host bindings for auth,
  storage and crypto; everything programs use comes from here

## Build & test

```bash
cargo test                # default members (unit + harness + regression suites)
cargo test -p e2e-tests   # end-to-end + adversarial suites against an L1 build
cargo clippy --all-targets -- -D warnings
```

## Security

Audit-lite findings (allowance ordering, dust, overflows, DNS owner-zero) are
fixed with regression pins; known residuals (bearer sessions, permissionless
swaps) are documented in program headers. External audit pending. Testnet
only. **Never open a public issue for a suspected vulnerability** — report
via [`SECURITY.md`](SECURITY.md).

## Contributing · License

Keep tests green, no weakening to pass. MIT **or** Apache-2.0
([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).
