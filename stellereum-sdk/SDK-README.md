# stellereum-sdk — minimal canonical tx-builder SDK

New-crate SDK that kills **B2 ("no SDK, wallets hand-roll bincode")**.
Five shapes, nothing more — every byte comes from the node's own constructors,
so SDK output is definitionally canonical.

> **Unaudited testnet — do not use real funds.** No independent external audit
> has completed for the network or this SDK.

## Install

```toml
[dependencies]
stellereum-sdk = { path = "../stellereum-sdk" }
```

Requires the local `stellereum` crate (path dependency, read-only reuse —
this SDK never modifies node or wallet protocol code). Builds offline against
the crates already in the workspace lockfile.

## The five builders + helpers

| Builder | Opcode | Notes |
| --- | --- | --- |
| `TxBuilder::transfer(to, amount)` | (plain payload) | native STELL |
| `TxBuilder::token_transfer(token_id, to, amount)` | `SysCallTokenTransfer` | + `token_approve` (`SysCallTokenApprove`), `token_transfer_from` (`SysCallTokenTransferFrom`) — both opcodes exist in `src/svm.rs` |
| `TxBuilder::stake_bond(validator, amount)` | `SysCallStake` | + `delegate` (`SysCallDelegate`), `begin_undelegate` (`SysCallBeginUndelegate`), `undelegate_withdraw` (`SysCallUndelegate`) — all trivially adjacent, all included |
| `TxBuilder::contract_deploy(code)` | `SysCallDeployContract` | address via `predict_contract_address` = the node's own `contract_address` (imported, never reimplemented) |
| `TxBuilder::contract_call(contract, method, abi, args, value)` | `SysCallCallContractArgs` | calldata via the node's own `ContractAbi::encode_args` |

Every builder: `.nonce(n)` · `.gas_limit(n)` (default: the node's own
`opcode_gas` / `GAS_BASIC_TRANSFER`) · `.shards(s, t)` · `.chain_id(id)` ·
`.unbound_legacy()` · `.sign(&key)`.

Every signed tx: `.fee_estimate_params()` · `.fee_estimate(rpc_url)` ·
`.sign` is really `.sign(key)` on the builder: `Ed25519 | Falcon-512 | Hybrid`
via the node's `post_quantum` primitives · `.to_bytes()` (exact wire bytes) ·
`.tx_hash()` / `.tx_hash_hex()` · `.verify()` · `.submit(rpc_url)` (POSTs
`stell_sendRawTransaction` with `{"tx": hex}`, returns the hash).

Deliberately out of scope: `SysCallClaimRewards` / key rotation (operator
flows), priority bids, session-key and EVM envelopes. See the
"Notes on what is deliberately NOT in scope" section in `src/lib.rs`.

## When to use `unbound_legacy` — never in prod

Envelopes are **chain-id bound by default** (`chain_id` 5757). The bound
envelope is what the wallet builds (`wallet.rs::create_bound_*`) and what
admission meters toward requiring (A14 rollout: warn+meter today, require
bound in phase 3).

`TxBuilder::….unbound_legacy()` recovers the old replayable bytes for
offline/legacy use only. It prints a loud warning on every use, and an
unbound transaction verifies today but fails
`verify_signature_for_chain(id, true)` — i.e. it will be refused once
phase 3 lands. **Never use in production.**

## Example 1 — transfer

```rust
use stellereum_sdk::{SdkKey, TxBuilder};

let key = SdkKey::ed25519([0x42u8; 32]);
let to = [0x99u8; 32];
let signed = TxBuilder::transfer(to, 1_000)
    .nonce(5) // read from stell_getBalance
    .sign(&key)?;

assert!(signed.is_bound());
let hash: String = signed.submit("http://127.0.0.1:8545")?;
println!("admitted: {hash}");
```

## Example 2 — token transfer (with fee estimate first)

```rust
use stellereum_sdk::{SdkKey, TxBuilder};

let key = SdkKey::ed25519([0x42u8; 32]);
let token = hex::decode("...64 hex chars...")?;
let token_id: [u8; 32] = token.try_into().map_err(|_| "bad token id")?;

let signed = TxBuilder::token_transfer(token_id, [0x22u8; 32], 250)
    .nonce(7)
    .sign(&key)?;

// Read-only: {"tx": hex} via stell_estimateFee — no state moves.
let est = signed.fee_estimate("http://127.0.0.1:8545")?;
println!("fee: {} (base {})", est.estimated_fee, est.base_fee);
let hash = signed.submit("http://127.0.0.1:8545")?;
println!("admitted: {hash}");
```

## Example 3 — stake bond (Falcon-512, post-quantum)

```rust
use stellereum_sdk::{SdkKey, TxBuilder};

let key = SdkKey::falcon_from_seed([0x77u8; 32]);
let validator = [0x66u8; 32];
let signed = TxBuilder::stake_bond(validator, 10_000)
    .nonce(1)
    .sign(&key)?;

assert!(signed.verify());
println!("bound pq stake: {}", signed.tx_hash_hex());
```

## Example 4 — contract deploy (deterministic address)

```rust
use stellereum_sdk::{predict_contract_address, SdkKey, TxBuilder};

let key = SdkKey::ed25519([0x42u8; 32]);
let code: Vec<u8> = std::fs::read("contract.wasm")?;
let signed = TxBuilder::contract_deploy(code).nonce(9).sign(&key)?;

// Same function the node uses — import, don't reimplement.
let lands_at = predict_contract_address(&key.address(), 9);
println!("deploys at: {}", hex::encode(lands_at));
let hash = signed.submit("http://127.0.0.1:8545")?;
println!("admitted: {hash}");
```

## Example 5 — contract call with ABI-typed args

```rust
use stellereum_sdk::{AbiMethod, AbiParam, AbiType, AbiValue, ContractAbi, SdkKey, TxBuilder};

let mut abi = ContractAbi::new();
abi.add_method(AbiMethod::mutating(
    "transfer",
    vec![
        AbiParam::new("to", AbiType::Address),
        AbiParam::new("amount", AbiType::U64),
        AbiParam::new("memo", AbiType::String),
    ],
    AbiType::Bool,
));

let key = SdkKey::ed25519([0x42u8; 32]);
let contract = [0xABu8; 32];
let args = vec![
    AbiValue::Address([0x01u8; 32]),
    AbiValue::U64(1234),
    AbiValue::String("memo".into()),
];
let signed = TxBuilder::contract_call(contract, "transfer", &abi, &args, 0)?
    .nonce(3)
    .sign(&key)?;

let hash = signed.submit("http://127.0.0.1:8545")?;
println!("admitted: {hash}");
```

## Test evidence

`cargo test` in this crate (12 tests, all passing):

* **Byte-equality, all five shapes**: `transfer`, `token_transfer`,
  `token_approve`, `token_transfer_from`, `stake_bond`, `delegate`,
  `begin_undelegate`, `undelegate_withdraw`, `contract_deploy`,
  `contract_call` — SDK `to_bytes()` == hand-built node `Transaction`
  bytes, and `tx_hash()` agrees (Ed25519 is deterministic, so full equality
  holds; see `tests/canonical.rs`).
* **Bound-by-default**: every builder carries the CH1 envelope without
  opt-in; `.unbound_legacy()` drops it (with the warning), still verifies,
  but fails the strict `verify_signature_for_chain(id, true)` check.
* **Fee-estimate param shape**: `fee_estimate_params()` is exactly
  `{"tx": hex}` — the shape `handle_estimate_fee`'s raw-transaction arm
  reads (`params["tx"]` → hex → `bincode::decode::<Transaction>`); the test
  replays that decode and the documented answer shape parses.
* **Sign+verify round trip per scheme**: Ed25519, Falcon-512 and Hybrid —
  bound and unbound — verify via the same `verify_signature` /
  `verify_signature_for_chain` admission uses; tampered bytes fail;
  wrong-chain fails.
* **Submit shape**: `{"tx": hex}` is what the `stell_sendRawTransaction`
  dispatch arm reads (`params["tx"].as_str()`, else `"missing tx"`).

No test touches a live network: no RPC is called, nothing is committed.
