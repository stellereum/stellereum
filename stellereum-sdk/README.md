# stellereum-sdk

Thin, client-only Rust SDK for Stellereum: Falcon-512 keys, `PQ1` transaction
construction and signing, `SF1` session grants, EVM binding/carrier payloads,
governance payloads, and a synchronous `stell_*` JSON-RPC client.

[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.3.0-blue)](Cargo.toml)
[![Network](https://img.shields.io/badge/network-testnet-yellow)](https://docs.stellereum.org/get-started/networks)
[![Audit](https://img.shields.io/badge/audit-none%20yet-red)](https://docs.stellereum.org/security/status)

## What it is / what it is not

- **Is** a wallet- and dApp-facing crate. It reimplements only the wire pieces
  a client mints: the Falcon-512 key container, the `PQ1`/`SF1` envelopes, the
  supported opcodes, signing preimages, the fork-id mirror, and the JSON-RPC
  client.
- **Is not** a node or consensus library. The node crate is an optional
  dependency used only by the `node-parity` test feature; a default build does
  not link tokio, axum, sled or wasmi.
- **Is not** an HSM, MPC or hardware-wallet integration. The key file is
  plaintext JSON written with mode `0600`.
- **Is not** the validator remote-signing seam. `RemoteSigner` lives in the
  node crate (`stellereum/src/remote_signer.rs`) for consensus vote keys; this
  SDK exposes no `RemoteSigner` and does not sign validator votes.
- **Is not** an audited product. It ships draft contract-deploy builders
  (`TxBuilder::contract_deploy` / `contract_deploy_with_abi`), but the
  ABI-persisting variant is gated off on today's chain; see
  [Contract deployment](#contract-deployment).

## Install and build

Use a path dependency until the crate is published:

```toml
# Cargo.toml
[dependencies]
stellereum-sdk = { path = "../stellereum-sdk" }
```

Build the thin client, run the client tests, and install the CLI:

```bash
cd stellereum-sdk

cargo build
cargo test                          # client tests, no node crate
cargo test --features node-parity   # + byte-for-byte parity with the node
cargo clippy --all-targets -- -D warnings

cargo build --release --bin stellereum-sdk-cli
cargo install --path .              # optional: puts stellereum-sdk-cli on PATH
```

`node-parity` is opt-in because it compiles the node crate:

```toml
# Cargo.toml of a parity test harness
[dev-dependencies]
stellereum-sdk = { path = "../stellereum-sdk", features = ["node-parity"] }
```

## Quickstart

Create and fund a key first:

```bash
stellereum-sdk-cli keygen --out wallet.json
stellereum-sdk-cli address --key wallet.json
```

Then build, sign, submit, and wait for a receipt:

```rust
use std::time::Duration;
use stellereum_sdk::prelude::*;

fn main() -> Result<(), stellereum_sdk::SdkError> {
    let key = FalconKeypair::load_key_file(std::path::Path::new("wallet.json"))?;
    println!("sender: {}", key.address_stl57());

    let mut wallet = Wallet::connect(key, "http://127.0.0.1:8545");

    // `transfer` fills the nonce, chain id and the node's current base floor.
    let signed = wallet.transfer([0x22; 32], 1_000_000)?;
    signed.verify()?;

    let outcome = wallet.submit(&signed, &RetryPolicy::default())?;
    let receipt = wallet.rpc().wait_for_receipt(
        &outcome.tx_hash,
        Duration::from_secs(60),
        Duration::from_secs(1),
    )?;

    println!("tx {} status {}", outcome.tx_hash, receipt.status);
    Ok(())
}
```

A retry resends the **same** signed bytes; it never re-signs or advances the
nonce. The wallet's nonce cache advances only after the node accepts the
transaction (or answers “already in mempool”).

## API surface

### Keys, envelopes and builders

| API | Description |
| --- | --- |
| `FalconKeypair::generate/load_key_file/save_key_file` | Falcon-512 key generation and versioned JSON key file I/O (mode `0600`). |
| `FalconKeypair::address/address_hex/address_stl57` | 32-byte address and its hex / `Stl57…` forms. |
| `FalconKeypair::sign/verify` | Sign a message and verify against the key. |
| `PqEnvelope::explicit/explicit_with_chain` | `PQ1` envelope carrying the public key; the builder adds the `45_000` gas activation surcharge for this form. |
| `PqEnvelope::implicit/implicit_with_chain` | `PQ1` envelope omitting the public key; no activation surcharge. |
| `PqEnvelope::encode/decode` | Wire encoding and decoding. |
| `TxBuilder::transfer(to, amount)` | Native value transfer (empty payload). |
| `TxBuilder::contract_call(contract, method, args, value)?` | `SysCallCallContractArgs` with typed `CallArg`s (ABI-encoded calldata). |
| `TxBuilder::contract_deploy(code)` | `SysCallDeployContract` (discriminant 19); self-addressed with `amount == 0`. |
| `TxBuilder::contract_deploy_with_abi(code, abi_json)` | `SysCallDeployContractWithAbi` (discriminant 65); gated, see below. |
| `contract_deploy_gas(code_len)` / `contract_deploy_with_abi_gas(code_len, abi_len)` | Deploy gas helpers: `2_000 + 2/byte`, plus `2/byte` of ABI capped at 64 KiB. |
| `MAX_CONTRACT_ABI_BYTES` / `OP_DEPLOY_CONTRACT` / `OP_DEPLOY_CONTRACT_WITH_ABI` | `65_536` / `19` / `65`. |
| `TxBuilder::stake(validator, amount)` | `SysCallStake`. |
| `TxBuilder::unjail(validator, top_up)` | Optional `SysCallStake` followed by `SysCallUnjail`. |
| `TxBuilder::gov_propose(id, title, action, height)?` | `SysCallGovPropose`; self-addressed, no value. |
| `TxBuilder::gov_vote(id, choice, height)` | `SysCallGovVote`; self-addressed, no value. |
| `TxBuilder::nonce/chain_id/base_fee/gas_limit/priority_fee_per_gas` | Fee and replay-domain setters. |
| `TxBuilder::shards(source, target)` | Source and target shard ids. |
| `TxBuilder::implicit/explicit` | Choose the envelope form. |
| `TxBuilder::unbound` | Replayable envelope; testing only, prints a warning. |
| `TxBuilder::sign(&key)` | Validate the chain/fork guard, sign, self-verify, return `SignedTx`. |
| `TxBuilder::sign_with_session(&session_key, &grant)` | Sign a delegated `SF1` transaction. |
| `EvmBindingBuilder::new(identity, evm_address, proof)?` | `SysCallBindEvmAddress`; requires a 65-byte secp256k1 proof. |
| `EvmCarrierBuilder::new(identity, raw_evm_tx, to_pq)?` | `SysCallEvmCarrier`; nonce and value come from the EVM intent. |
| `SessionGrant::new(master, session_pubkey, valid_until, max_gas, scope, max_value, chain_id)?` | Mint an `SF1` master grant. |
| `GovAction` / `VoteChoice` | Governance action and vote enums mirrored from the node. |

Every builder runs the protocol/fork guard before signing.
`ProtocolIdentity::local()` is chain `5757`, protocol `1.0`, consensus ruleset
v7, fork id `0x3ae00ebc`. A foreign chain id is `SdkError::ChainIdMismatch`; a
foreign fork id is `SdkError::ForkIdMismatch`. Use `.identity(identity)` or
`Wallet::with_identity` for a different node identity.

### Contract deployment

`TxBuilder::contract_deploy(code)` and
`TxBuilder::contract_deploy_with_abi(code, abi_json)` mint the two deploy
opcodes. Both build a self-addressed (`to == from`) transaction with
`amount == 0`; the payload is `bincode(Vec<OpCode>)` carrying exactly one
element.

Wire layout of that element (little-endian, `bincode 1.3`):

```text
payload (Vec<OpCode>): u64 LE 1 || <one opcode>
SysCallDeployContract        (19): u32 19 || code (u64 len || bytes)
SysCallDeployContractWithAbi (65): u32 65 || code (u64 len || bytes)
                                            || abi_json (u64 len || bytes)
```

Limits: `abi_json` is a UTF-8 JSON `ContractAbi` manifest
(`{"methods":…,"events":…}`) and `MAX_CONTRACT_ABI_BYTES = 65_536` (64 KiB).
The VM rejects a larger blob at apply and the gas helper prices
`min(abi_len, 65_536)`. The Rust builder itself does not validate the JSON or
reject an oversized manifest; `ContractAbi::from_json` and the 64 KiB cap are
enforced by the VM and by the `stell_deployContract` preview.

Gas:

```text
contract_deploy_gas(n)             = 2_000 + 2 * n
contract_deploy_with_abi_gas(c, a) = contract_deploy_gas(c)
                                   + 2 * min(a, 65_536)

gas_limit = max(opcode_gas, base_fee, 280_000)
          + 45_000 (explicit PQ1)
          + priority_fee_per_gas
```

A tiny module therefore still declares 325,000 gas: the 280,000 frozen floor
plus the explicit-envelope surcharge.

```rust
use stellereum_sdk::{FalconKeypair, RpcClient, TxBuilder};

let key = FalconKeypair::load_key_file(std::path::Path::new("wallet.json"))?;
let rpc = RpcClient::new("http://127.0.0.1:8545");
let code = std::fs::read("token.wasm")?;

// Plain deploy: the form that executes on today's chain.
let signed = TxBuilder::contract_deploy(code.clone()).nonce(7).sign(&key)?;
let hash = rpc.send_raw(&signed)?;
```

```rust
// ABI-carrying deploy (discriminant 65). It mints and signs, but see the gate.
let abi_json = br#"{"methods":[],"events":[]}"#.to_vec();
let signed = TxBuilder::contract_deploy_with_abi(code, abi_json)
    .nonce(7)
    .sign(&key)?;
```

**Gate: `SysCallDeployContractWithAbi` is INERT today.** Execution calls
`chain_spec::contract_abi_onchain_active_at(height)` before deploying; when it
is false the opcode reverts with
`SysCallDeployContractWithAbi inactive at height <h>`. The compiled
`CONTRACT_ABI_ONCHAIN_ACTIVATION_HEIGHT` is `u64::MAX`, and that helper returns
`false` for **every** height — including `u64::MAX` — when the gate is
`u64::MAX` (`GatedOff`). Consequences:

- On today's chain a `contract_deploy_with_abi` transaction is admitted and can
  be previewed, but it reverts when a block applies it.
- Use `TxBuilder::contract_deploy` and submit. No manifest is committed, so
  `stell_getContractAbi` answers `abi: null` for a plain deploy (it stays
  `null` until a height-armed chain executes the ABI variant).
- `stell_deployContract`'s signed-`tx` preview reports `has_abi: true` when the
  transaction carries the ABI opcode. That is a preview only: it deploys
  nothing, files no receipt, and does not consult the activation gate, so it
  can succeed for a transaction that would revert at apply.
- The CLI `stellereum contract deploy` has no `--abi` flag and always builds
  the plain opcode.

`Wallet` has no deploy convenience (it wraps transfer, contract call, staking,
EVM and governance). For a deploy, sign the `TxBuilder` and submit with
`RpcClient::send_raw` (or `Wallet::rpc()`), as above.

### Signed transactions and reads

| API | Description |
| --- | --- |
| `SignedTx::to_hex/to_bytes` | Encode the signed transaction. |
| `SignedTx::tx_hash_hex` | Canonical transaction hash. |
| `SignedTx::verify/verify_with_key` | Verify the envelope and signature; `verify` covers explicit envelopes, `verify_with_key` also covers implicit ones. |
| `SignedTx::from/to/nonce/gas_limit/amount/chain_id` | Transaction accessors. |
| `SignedTx::payload_bytes` | Raw payload bytes committed by the signature. |
| `RpcClient::account/nonce/balance` | `stell_getBalance`. |
| `RpcClient::base_fee` | `stell_baseFee`. |
| `RpcClient::chain_id` | `stell_chainId`. |
| `RpcClient::validators` | `stell_getValidators`. |
| `RpcClient::block/block_number` | `stell_getBlock` / `stell_blockNumber`. |
| `RpcClient::receipt/transaction_status` | Receipt and status reads. |
| `RpcClient::estimate_fee` | `stell_estimateFee` for an already-signed transaction. |
| `RpcClient::send_raw/send_raw_hex` | `stell_sendRawTransaction`. |
| `RpcClient::send_with_retry` | Resend the same signed bytes with backoff. |
| `RpcClient::wait_for_receipt/send_and_wait` | Poll until committed or timeout. |
| `RpcClient::pq_key` | Query a validator's PQ key record. |

### Wallet

| API | Description |
| --- | --- |
| `Wallet::connect(key, url)` / `Wallet::new(key, rpc)` | Bind a key to an RPC endpoint. |
| `Wallet::with_chain_id/with_identity` | Override the bound chain or full protocol identity. |
| `Wallet::transfer/contract_call/stake/unjail` | Prepare, sign and return a `SignedTx`. |
| `Wallet::evm_binding/evm_carrier` | Build and sign EVM registry/carrier transactions. |
| `Wallet::gov_propose/gov_vote` | Build and sign governance transactions. |
| `Wallet::prepare/sign/build` | Separate fee/nonce preparation from signing. |
| `Wallet::build_session` | Sign with a delegated session key and grant. |
| `Wallet::submit/submit_and_wait` | Submit with retries and optionally wait for the receipt. |
| `Wallet::next_nonce/reset_nonce` | Read or invalidate the conservative nonce cache. |
| `Wallet::check_affordable` | Check amount plus gas against the account balance. |

### Fee rule

The builder computes:

```text
gas_limit = max(opcode_gas, base_fee) + (45_000 if explicit PQ1) + priority
```

For the node's exact answer including the sender's failure penalty, submit the
signed transaction to `stell_estimateFee` (`RpcClient::estimate_fee`).

## CLI and signing server

The crate ships one binary, `src/bin/stellereum-sdk-cli.rs`. There is no
`examples/` directory.

| Command | Description |
| --- | --- |
| `stellereum-sdk-cli keygen [--out KEY.json]` | Generate a key; write to a file or print JSON to stdout. |
| `stellereum-sdk-cli address --key KEY.json` | Print `Stl57`, hex address, and public key. |
| `stellereum-sdk-cli sign --key KEY.json [--request REQ.json]` | Sign a JSON `{"tx":{…}}` request; reads stdin when `--request` is omitted. |
| `stellereum-sdk-cli sign-digest --key KEY.json [--digest 0x…]` | Sign a 32-byte digest; used for inner EVM statements. |
| `stellereum-sdk-cli serve --key KEY.json [--listen 127.0.0.1:8787]` | Run the loopback HTTP signing helper. |
| `stellereum-sdk-cli version` | Print the crate version. |

`sign` accepts `transfer`, `contract_call`, `stake`, `unjail`, `evm_binding`,
`evm_carrier`, `gov_propose`, `gov_vote`, and `prepared`. It writes a JSON
success object or `{"ok":false,"error":{…}}` and exits non-zero on refusal.

`serve` exposes:

| Endpoint | Description |
| --- | --- |
| `GET /health` | Liveness plus the signer's `Stl57…` address. |
| `POST /sign` | Sign a `SignRequest` body. |
| `POST /sign-digest` | Sign a 32-byte hex digest. |

If `STELL_SDK_SIGNER_TOKEN` is set, both POST endpoints require
`Authorization: Bearer <token>`. The helper is plain HTTP on loopback; keep it
there.

The TypeScript package ([`sdk-js`](../sdk-js/README.md)) invokes this binary as
`stellereum-sdk-cli sign --key …` with the intent on stdin, or POSTs the same
JSON to `serve`. The Falcon key never enters JavaScript; only the intent and
signed bytes cross the process boundary.

## Configuration

| Key / flag | Default | Description |
| --- | --- | --- |
| Cargo feature `node-parity` | off | Compile the node crate and run byte-parity tests. |
| `--key <path>` | required for `address`, `sign`, `sign-digest`, `serve` | JSON key file. |
| `--out <path>` | stdout | `keygen` output path. |
| `--request <path>` | stdin | `sign` request file. |
| `--digest <hex>` | stdin JSON | `sign-digest` input. |
| `--listen <addr>` | `127.0.0.1:8787` | `serve` bind address. |
| `STELL_SDK_SIGNER_TOKEN` | unset (no auth) | Bearer token required by `serve` POST endpoints. |

Key files are versioned plaintext JSON (`version: 1`, scheme `falcon512`) and
are created with mode `0600` on Unix. They contain the 897-byte public key and
the PQClean secret key. A node operator's expanded private-key container is a
different format and is not importable; public keys and signatures are
interoperable.

## Testing

```bash
cd stellereum-sdk

cargo test
cargo test --features node-parity
cargo clippy --all-targets -- -D warnings
```

The SDK suite is an independent process and does not need the node crate's
serial-lib wrapper; it can run alongside other workspace suites. The
`node-parity` suite is heavier because it compiles the node crate.

## Documentation

- [Rust SDK guide](https://docs.stellereum.org/sdk/rust)
- [Accounts and fees](https://docs.stellereum.org/core-concepts/accounts-and-fees)
- [JSON-RPC reference](https://docs.stellereum.org/api/json-rpc)
- [Security status](https://docs.stellereum.org/security/status)
- [Security policy](../SECURITY.md)
- [License](LICENSE) — MIT OR Apache-2.0
  ([MIT](LICENSE-MIT), [Apache-2.0](LICENSE-APACHE))

## Status

Testnet only. No external audit. The key file is plaintext and there is no HSM
or hardware-wallet path. The deploy builders are draft surface: the plain
opcode works, while the ABI-persisting opcode is gated off (`u64::MAX`) and has
never executed on a live chain. Treat the SDK as unaudited client software and
do not use it with funds you cannot afford to lose.

Open work before any production use: an external audit; arming and testing the
`CONTRACT_ABI_ONCHAIN` gate (plus a typed raw-calldata call path for the
production-shape contract entrypoints); and a vetted remote/HSM story for
wallet keys. `RemoteSigner` in the node crate is for validator consensus keys,
not for this SDK's wallet keys.
