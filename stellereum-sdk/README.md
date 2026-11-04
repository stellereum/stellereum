# stellereum-sdk

> Testnet software — no real funds, no mainnet yet, no external audit yet.

Minimal canonical transaction-builder SDK for Stellereum: transfers, tokens,
staking, contract deploy and calls. Every byte comes from the node's own
constructors, so SDK output matches consensus encoding by construction.
Full reference: [`SDK-README.md`](SDK-README.md).

<p align="center">
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange" alt="License"/></a>
</p>

## Builders

- `TxBuilder::transfer` — native STELL transfers
- `TxBuilder::token_transfer` / `token_approve` / `token_transfer_from` — STS-20 flows
- `TxBuilder::stake_bond` / `delegate` / `begin_undelegate` / `undelegate_withdraw` — staking lifecycle
- `TxBuilder::contract_deploy` — deploys with node-derived addresses (`predict_contract_address`)
- `TxBuilder::contract_call` — calls with node-encoded calldata (`ContractAbi::encode_args`)

Every builder: `.nonce(n)` · `.gas_limit(n)` · `.shards(s, t)` · `.chain_id(id)` ·
`.sign(&key)` (Ed25519, Falcon-512 or Hybrid) · `.to_bytes()` (exact wire bytes) ·
`.tx_hash_hex()` · `.verify()` · `.fee_estimate(rpc_url)` · `.submit(rpc_url)`.

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

No external audit yet. Testnet only. Signed payloads never leave your machine
except through `.submit()` to an RPC you choose. **Never open a public issue
for a suspected vulnerability** — report via [`SECURITY.md`](SECURITY.md).

## Contributing · License

Keep tests green. MIT **or** Apache-2.0
([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)).
