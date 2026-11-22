---
title: Smart contracts overview
description: What a Stellereum smart contract is, how it is deployed and executed, and what the current preview/testnet status means for you.
---

# Smart contracts on Stellereum

A Stellereum smart contract is a **WebAssembly module** that lives at a deterministic 32-byte
address, owns a key-value storage map and a native balance, and exports integer-only methods.
It runs inside the `wasmi` interpreter under a fuel meter, with a deliberately tiny, closed host
interface. There is no EVM bytecode, no account-abstraction precompile, and no synchronous
cross-contract call in the current runtime.

```text
Contract {
  address      : 32 bytes    sha256("STELL_CONTRACT" || creator || nonce)
  creator      : 32 bytes    the account that deployed it
  code_hash    : 32 bytes    sha256(code)
  code         : wasm bytes  at most 2 MiB
  storage      : i64 -> i64  at most 4,096 distinct keys
  balance      : u64         nano-STELL held by the contract
  paused       : bool        creator-only engine-level stop (no RPC setter)
  abi          : optional    typed interface manifest (STELL-ABI v1)
  source_hash  : optional    BLAKE3 of registered source text
}
```

::: warning Status: preview / testnet, no external audit
The contract engine, the ABI layer and the RPC surface are implemented and tested, but the
feature is still **preview-grade**:

- it has **not** had an independent external audit;
- the bundled reference contracts in `stellereum-contracts/contracts/` are explicitly
  **demo-grade** and say *"DO NOT deploy with value without a full audit"* in their headers;
- one documented gap is that a block-carried deploy opcode carries **code only**, not an ABI
  manifest (see [`/contracts/abi`](/contracts/abi) and [`/contracts/deploy-and-call`](/contracts/deploy-and-call)).

Treat everything here as testnet behavior. Do not move value you cannot afford to lose.
:::

## The execution contract

The runtime makes five promises that every contract can rely on:

| Property | Rule |
| --- | --- |
| Deterministic | Same code + same storage + same call context ⇒ identical result on every node, every CPU. |
| Integer-only interface | Every export takes and returns `i64`. There is no ABI type for `f32`/`f64`. |
| Metered | Every instruction and every host call consumes fuel. A call cannot loop forever. |
| Closed sandbox | Only the 14 functions in the `host` module resolve. No wall clock, network, filesystem or host memory. |
| Exact arity | A method is dispatched by name **and** parameter count. An argument is never silently dropped. |

A method may export zero to eight `i64` parameters:

```text
(func (export "answer") (result i64) (i64.const 42))
(func (export "double") (param i64) (result i64) ...)
(func (export "sum3")   (param i64 i64 i64) (result i64) ...)
```

A Rust `extern "C" fn` maps one-to-one onto that shape. See
[`/contracts/rust`](/contracts/rust) for the full toolchain walkthrough and
[`/contracts/wat`](/contracts/wat) for hand-written modules.

## Lifecycle

```text
        WAT source                     Rust source
            │                              │
            │ wat2wasm                     │ cargo build --target wasm32-unknown-unknown
            ▼                              ▼
                     module.wasm  (validated: ≤ 2 MiB, ≤ 128 memory pages,
                                  imports resolvable, start section bounded)
                                    │
                                    │ signed SysCallDeployContract transaction
                                    │ submitted with stell_sendRawTransaction
                                    ▼
                     contract actor @ sha256("STELL_CONTRACT" || creator || nonce)
                                    │
             ┌──────────────────────┼───────────────────────────┐
             │                      │                           │
        call (state write)     query (read-only)          events / receipt
   SysCallCallContract      stell_runGetMethod        stell_getEvents
   SysCallCallContractArgs  ≤ 5,000,000 fuel          stell_getContractReceipt
             │                      │
             ▼                      ▼
      storage / balance       typed or raw answer
      events / outbound msgs
             │
             ▼
      source verification (stell_verifyContractSource → stell_registerContractSource)
             │
             ▼
      upgrade by redeploy: new address + explicit state migration + retire old contract
```

Three consequences of this design are worth internalizing early:

1. **Deployment and calls are transactions, not RPC side effects.** `stell_deployContract` and
   `stell_callContract` are *previews*. They validate and simulate, then drop the request. Only a
   block applying a signed transaction changes state. See
   [`/contracts/deploy-and-call`](/contracts/deploy-and-call).
2. **Contracts do not call each other synchronously.** There is no `call` host import. The only
   inter-contract primitive is an asynchronous outbound message (`host.send_message`) that the
   engine routes after the call succeeds, TON-style.
3. **There is no in-place upgrade.** `Contract.code` is immutable once deployed. Upgrading means a
   new contract at a new address, a deliberate migration, and retiring the old one (the registry's
   `pause` flag is engine-level only; no RPC or opcode sets it today). See
   [`/contracts/verification-and-upgrade`](/contracts/verification-and-upgrade).

## What "state" means

Contract state is not one opaque blob. The consensus commitment includes, per contract, the
creator, code hash, `created_at`, `paused` flag, the ABI manifest, the registered source hash, and
every storage slot in **signed-key order**. The Patricia trie additionally commits the code hash,
ABI manifest and source fingerprint under namespaced keys:

```text
sha256("STELL_CONTRACT_CODE"   || address) -> code_hash
sha256("STELL_CONTRACT_ABI"    || address) -> abi_json
sha256("STELL_CONTRACT_SOURCE" || address) -> source_hash
```

Storage slots are folded into the consensus-commitment digest rather than being individually
provable leaves; there is no per-slot Merkle proof today. That matters for light clients and for
migration tooling — see [`/contracts/execution-model`](/contracts/execution-model#deterministic-state-root).

## What you can build with it

The runtime is intentionally small, so the useful patterns are the ones the bundled contracts
demonstrate:

| Pattern | Reference contract | What it shows |
| --- | --- | --- |
| Fungible token | STS-20 (`sts20-token`) | balances, allowances, fee leg, supply accounting, authenticated transfers |
| Name registry + auction | STL-DNS (`stl-dns`) | state machines in integer slots, reserved names, ownership transfer |
| Constant-product AMM | Liquidity Pool (`liquidity-pool`) | `u128` math inside an `i64` world, LP shares, pro-rata payout |
| Account abstraction | Account Object (`account-object`) | owner/guardian recovery, rentals, session budgets |

All four are reference implementations, not audited products. Each page in
[`/contracts/standards`](/contracts/standards) lists its storage layout, entry points, events and
the caveats written into its own source header.

## Reading order

| Page | Read it when you want to… |
| --- | --- |
| [Execution model](/contracts/execution-model) | understand fuel, limits, reverts, panics and determinism |
| [Rust contracts](/contracts/rust) | build a contract with the SDK and the wasm32 target |
| [WAT contracts](/contracts/wat) | write or inspect a minimal module by hand |
| [Host functions](/contracts/host-functions) | know the exact import signatures and fuel prices |
| [ABI manifest & wire format](/contracts/abi) | type a contract's interface and encode calldata |
| [Deploy and call](/contracts/deploy-and-call) | go from preview to a real signed transaction |
| [Reference standards](/contracts/standards) | study or fork STS-20, STL-DNS, the AMM and Account Object |
| [Verification and upgrade](/contracts/verification-and-upgrade) | publish source, verify a build, plan a migration |

## Source map

The behavior documented here is implemented in:

| Path | Contents |
| --- | --- |
| `stellereum/src/contract.rs` | engine config, registry, limits, `host_linker`, fuel constants, `ContractError` |
| `stellereum/src/contract_abi.rs` | manifest, `AbiValue`, STELL-ABI v1 encoding |
| `stellereum/src/contract_source.rs` | source rebuild, fingerprint, registration signature |
| `stellereum/src/rpc/contracts.rs` | contract RPC arms (previews, getters, ABI, receipts, source) |
| `stellereum/src/svm.rs` | `SysCallDeployContract`, `SysCallCallContract*`, gas table |
| `stellereum-contracts/crates/stellereum-contract-sdk/` | `no_std` Rust bindings and storage helpers |
| `stellereum-contracts/contracts/` | the four reference contracts |

::: tip Terminology
This documentation uses **fuel** for the `wasmi` budget consumed inside a call and **gas** for the
SVM transaction budget. The remaining transaction gas is handed to `wasmi` as its fuel budget, so
fuel can never exceed what the sender paid for.
:::

## Next

Read the [Execution model](/contracts/execution-model) next for fuel, limits and revert semantics. [Writing contracts in Rust](/contracts/rust) is the fastest path to a deployable module.
