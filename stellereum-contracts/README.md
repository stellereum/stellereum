# stellereum-contracts

Reference WebAssembly smart contracts for Stellereum, plus the `no_std`
`stellereum-contract-sdk` host bindings they are built with: STS-20 tokens,
STL-DNS names, a constant-product liquidity pool, and account objects.

[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange)](LICENSE)
[![Target](https://img.shields.io/badge/target-wasm32--unknown--unknown-blue)](Cargo.toml)
[![Network](https://img.shields.io/badge/network-testnet-yellow)](https://docs.stellereum.org/get-started/networks)
[![Status](https://img.shields.io/badge/contracts-demo--grade-red)](https://docs.stellereum.org/contracts/overview)
[![Audit](https://img.shields.io/badge/audit-none%20yet-red)](https://docs.stellereum.org/security/status)

## What it is / what it is not

- **Is** four reference programs and a small SDK that demonstrates the runtime's
  actual surface: integer-only exports, `i64` storage slots, events, and the
  authenticated `host.caller`.
- **Is** demo-grade. Every program header says **DO NOT deploy with value
  without a full audit**; the repository has internal auth, economic-abuse,
  proof-of-concept and regression suites, but **no external audit**.
- **Is not** an EVM/Solidity environment. There is no EVM bytecode, no
  synchronous cross-contract call, and no in-place upgrade; upgrade means a new
  deployment, migration, and retirement of the old address.
- **Is not** a production token/DNS/AMM product. The contracts use public
  integer account ids and packed `i64` arguments; they are reference patterns,
  not audited financial infrastructure.
- **Has no deploy builder in the Rust SDK.** `stellereum-sdk::Op` has no deploy
  variant. Deployment is a preview RPC plus a signed transaction whose payload
  is `SysCallDeployContract { code }`, built by the caller.

## Install and build

The workspace contains the SDK, the four contracts, and a separate e2e crate:

```text
stellereum-contracts/
├── Cargo.toml                    # workspace + release profile
├── crates/
│   ├── stellereum-contract-sdk/
│   └── e2e-tests/
└── contracts/
    ├── sts20-token/
    ├── stl-dns/
    ├── liquidity-pool/
    └── account-object/
```

```bash
cd stellereum-contracts

rustup target add wasm32-unknown-unknown

cargo test
cargo clippy --all-targets -- -D warnings
```

Build the four WASM artifacts:

```bash
cargo build --release --target wasm32-unknown-unknown \
  -p stl-dns -p sts20-token -p liquidity-pool -p account-object
```

| Crate | Artifact | Purpose |
| --- | --- | --- |
| `sts20-token` | `target/wasm32-unknown-unknown/release/sts20_token.wasm` | Fungible token with balances, allowances, mint/burn, and a 50 bps transfer fee. |
| `stl-dns` | `.../stl_dns.wasm` | Name registry with a length-based auction price grid and reserved names. |
| `liquidity-pool` | `.../liquidity_pool.wasm` | Constant-product AMM with LP shares and swap quotes. |
| `account-object` | `.../account_object.wasm` | Owner/guardian recovery, rentals, and session budgets. |
| `stellereum-contract-sdk` | library only | `no_std` host bindings and storage helpers. |

The release profile is workspace-wide: `opt-level = "z"`, `lto = true`,
`codegen-units = 1`, `panic = "abort"`, `overflow-checks = true`, and stripped
symbols. Keep `overflow-checks = true`: silent wrapping arithmetic can mint or
destroy balances.

## Quickstart

A real integration test against the STS-20 reference contract. Put it in
`contracts/sts20-token/tests/quickstart.rs` and run
`cargo test -p sts20-token --test quickstart`.

```rust
use stellereum_contract_sdk::{id_to_caller, reset_mock_state, set_mock_caller};
use sts20_token::{balance_of, init, transfer};

#[test]
fn transfer_moves_9950_after_the_50_bps_fee() {
    reset_mock_state();
    assert_eq!(init(1_000_000), 0);

    // Authenticate account id 1 as the caller; ids alone are not credentials.
    set_mock_caller(id_to_caller(1));

    // packed = from * 100_000_000 + to * 100_000 + amount
    let packed = 100_000_000 + 2 * 100_000 + 10_000;
    assert_eq!(transfer(packed), 1);

    assert_eq!(balance_of(2), 9_950);  // recipient
    assert_eq!(balance_of(99), 50);    // treasury fee
    assert_eq!(balance_of(1), 990_000);
}
```

Minimal contract skeleton:

```rust
#![no_std]

use stellereum_contract_sdk::{setup_wasm_panic_handler, StorageItem};

setup_wasm_panic_handler!();

const COUNT: StorageItem = StorageItem::new(1);

#[no_mangle]
pub extern "C" fn increment(_arg: i64) -> i64 {
    COUNT.update(|value| value.saturating_add(1))
}
```

Exports are dispatched by name **and** exact arity. Each parameter and return
value is `i64`; a Rust `extern "C" fn` maps one-to-one. The account-object
crate uses `extern "C-unwind"` so native tests can observe auth traps through
`catch_unwind`; on wasm a panic still lowers to `unreachable` and the host
reports a trapped call.

## API surface

### `stellereum-contract-sdk`

| Item | Description |
| --- | --- |
| `sload(key) -> i64` / `sstore(key, value)` | Raw persistent slot access. |
| `StorageItem::new(slot)` | Typed single-slot wrapper with `get`/`set`/`update`. |
| `StorageMap::new(base_slot)` | Keyed map with FNV-1a domain-separated slot derivation. |
| `emit(topic, value)` | Append an event. |
| `caller() -> [u8; 32]` | Authenticated transaction sender. |
| `caller_is(id) -> bool` | Fail-closed binding of a positive integer id to `caller()`. |
| `value() -> u64` | Native value attached to the call (host-dependent; not a reliable payable channel on the block path). |
| `setup_wasm_panic_handler!()` | Lower panics to a wasm trap. |
| `SUCCESS`, `ERR_*` | Conventional return codes (`-1` unauthorized, `-2` balance, `-3` argument, and so on). |
| `address::hash_domain/calculate_domain_hue` | STL-DNS domain id/hue helpers. |
| `address::BURN_ADDRESS`, reserved-domain lists | Zero address and protocol/system reserved names. |

Collision caution: `StorageMap` is a 63-bit FNV-1a fold, not a cryptographic
hash. Domain-separate key spaces with distinct `base_slot` values.

### Reference programs

| Program | Entry points |
| --- | --- |
| STS-20 | `init`, `decimals`, `total_supply`, `balance_of`, `allowance`, `approve`, `transfer`, `transfer_from`, `mint`, `burn`. |
| STL-DNS | `init`, `get_min_bid`, `get_hue`, `start_auction`, `place_bid`, `finalize_auction`, `resolve`, `set_target`, `transfer`. |
| Liquidity pool | `init`, `get_reserve_a`, `get_reserve_b`, `get_total_shares`, `shares_of`, `deposit`, `withdraw`, `swap_quote`, `swap_quote_b_for_a`, `swap_a_for_b`, `swap_b_for_a`. |
| Account object | `init`, `get_owner`, `get_guardian`, `get_pending_owner`, `transfer_ownership`, `rotate_guardian`, `initiate_recovery`, `cancel_recovery`, `finalize_recovery`, `set_tenant`, `revoke_rental`, `get_active_tenant`, `is_rental_active`, `create_session`, `update_session_budget`, `spend_with_session`, `revoke_session`, `is_session_active`, `get_session_budget`. |

Several methods pack multiple fields into one `i64` (for example
`from * 100_000_000 + to * 100_000 + amount`). The packing convention is part of
the contract's interface; callers must use the exact widths and bounds in the
source.

## Deploying

### Preview is not deployment

`stell_deployContract` validates the module, simulates a deploy on a clone, and
predicts the address. It **never** enters the mempool, writes a receipt, or
changes state. It requires the node's write token (`STELL_RPC_AUTH_TOKEN`),
including on loopback.

```bash
curl -s http://127.0.0.1:8545 \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer $STELL_RPC_AUTH_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "stell_deployContract",
    "params": {
      "sender": "0x<32-byte-creator-hex>",
      "code": "0x<hex-wasm>"
    }
  }'
```

The response includes `contract_address`, `contract_address_stl57`,
`code_hash`, `predicted: true`, `deployed: false`, and `preview_only: true`.
Pass `{"tx":"0x<hex bincode(Transaction)>"}` instead of `{sender, code}` to
verify an already-signed deploy transaction; the preview still drops it.

### Real deployment

A deploy is a normal signed transaction:

```text
from          = creator
to            = creator        (self-addressed)
amount        = 0
nonce         = the account nonce the transaction applies at
gas_limit     >= deploy gas and the mempool floor
payload       = vec![SysCallDeployContract { code }]
signature     = PQ1 envelope (Falcon-512)
```

Submit those bytes with `stell_sendRawTransaction`. The contract address is:

```text
sha256("STELL_CONTRACT" || creator[32] || nonce_be_u64)
```

It depends on the creator and nonce, not on the code. The runtime rejects code
above **2 MiB**.

There is no `TxBuilder::contract_deploy` and no deploy variant in
`stellereum-sdk::Op`; build the payload with the node's `OpCode` type or the
bincode layout directly. `SysCallDeployContract` carries **code only**: an ABI
manifest passed to the preview is not committed by block application, so
register it separately if your tooling needs it.

## Configuration

| Setting | Value | Description |
| --- | --- | --- |
| Target | `wasm32-unknown-unknown` | Required for deployable artifacts. |
| Crate type | `cdylib` + `rlib` | `cdylib` for wasm, `rlib` for native tests. |
| `panic` | `abort` | Panics lower to traps. |
| `overflow-checks` | `true` | Keep checked arithmetic in release. |
| `opt-level` / `lto` | `z` / `true` | Size-oriented build. |
| Max code size | 2 MiB | Enforced by the runtime. |
| Max distinct storage keys | 4,096 per contract | Runtime limit. |
| `STELL_RPC_AUTH_TOKEN` | node-side | Required by `stell_deployContract` / `stell_callContract` previews. |

There are no environment variables read by the contracts themselves. All
deployment and call inputs go through node RPC or signed transactions.

## Testing

```bash
cd stellereum-contracts

# Native unit + auth + economic-abuse + regression suites (default members).
cargo test

# End-to-end and adversarial suites against the node's L1 engine.
# Requires the four .wasm artifacts from the build step above.
cargo build --release --target wasm32-unknown-unknown \
  -p stl-dns -p sts20-token -p liquidity-pool -p account-object
cargo test -p e2e-tests

cargo clippy --all-targets -- -D warnings
cargo clippy -p e2e-tests --all-targets -- -D warnings
```

The native contract suites use the SDK's mock storage and mock caller; the e2e
suites deploy the built `.wasm` files into the node's in-memory state engine.
The contract and e2e suites are independent test processes and do not use the
node crate's serial-lib wrapper; they can run alongside other workspace suites.

## Documentation

- [Smart contracts overview](https://docs.stellereum.org/contracts/overview)
- [Writing contracts in Rust](https://docs.stellereum.org/contracts/rust)
- [Execution model](https://docs.stellereum.org/contracts/execution-model)
- [Reference standards](https://docs.stellereum.org/contracts/standards)
- [Deploy and call](https://docs.stellereum.org/contracts/deploy-and-call)
- [Security policy](SECURITY.md)
- [License](LICENSE) — MIT OR Apache-2.0
  ([MIT](LICENSE-MIT), [Apache-2.0](LICENSE-APACHE))

## Status

Demo-grade reference code. No external audit. The source headers explicitly say
not to deploy these programs with value without a full audit. Internal suites
cover authorization, economic abuse, overflow boundaries, and regression pins,
but they are not a substitute for an independent review.

Known residuals written into the sources:

- Session spend/update/revoke in the account object are bearer-style: they do
  not carry an authenticated caller field.
- Pool swaps are permissionless AMM mechanics by design; DNS auctions move no
  funds and are permissionless.
- STS-20 and the other programs use public integer account ids and packed
  arguments, not an address-typed ABI.
- There is no in-place upgrade and no ABI manifest in a block-carried deploy.

Before any value-bearing deployment: an external audit, a deploy/ABI workflow,
and a migration plan for the specific program.
