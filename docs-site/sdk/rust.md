---
title: Rust SDK
description: Build, sign, submit and verify Stellereum transactions with the stellereum-sdk crate.
outline: deep
---

# Rust SDK (`stellereum-sdk`)

`stellereum-sdk` is a **thin, client-only** crate for wallets and services that need to build, sign, submit and verify transactions without linking the node. It reimplements only the wire pieces a wallet mints — the Falcon-512 key container, the `PQ1` envelope, the supported opcodes, the signing preimages, the fork-id mirror and the `stell_*` JSON-RPC client — and a parity suite pins every byte against the node.

::: warning Testnet software
The crate is unaudited and the key file is **plaintext JSON at mode `0600`**.
There is no hardware-wallet, HSM or MPC integration in the SDK. Protect the
file or wrap it in an OS keystore.
:::

## Install

The crate lives in-tree at `stellereum-sdk/`. Use a path dependency until a
registry release is published:

```toml
# Cargo.toml
[dependencies]
stellereum-sdk = { path = "../stellereum-sdk" }
```

The node crate is an **optional** dependency used only by the parity tests:

```bash
cd stellereum-sdk

cargo test                          # thin client tests, no node crate
cargo test --features node-parity   # byte-for-byte parity with the node
cargo clippy --all-targets -- -D warnings
```

## Keys and addresses

```rust
use stellereum_sdk::prelude::*;

let key = FalconKeypair::generate()?;
key.save_key_file(std::path::Path::new("wallet.json"))?;

let key = FalconKeypair::load_key_file(std::path::Path::new("wallet.json"))?;
println!("hex      {}", stellereum_sdk::to_hex(&key.address()));
println!("Stl57    {}", key.address_stl57());
```

| Property | Value |
| --- | --- |
| Scheme | Falcon-512 (FIPS 206 / FN-DSA), scheme id `0x02` |
| Public key | 897-byte FIPS 206 encoding, header `0x09` |
| Signature | padded 666-byte Falcon-512, canonical chain header `0x29` |
| Address | `BLAKE3("STL_ADDR_V4" ‖ 0x02 ‖ pubkey(897) ‖ salt(16))` |
| `Stl57` form | base58(`address ‖ BLAKE3 checksum`), node-compatible |

`ML-DSA-44` (`0x03`) is disabled and refused by the node; only Falcon-512 is
live. The SDK normalizes the `0x29` signature header and the parity suite
verifies the result with the node.

::: danger Do not import a node operator key
The node stores expanded `(f, g, F, G, h)` polynomials. The SDK stores
PQClean `(f, g, F)` plus the public key. Public keys and signatures
interoperate; the **private container does not**. Generate a separate SDK key
for wallet use.
:::

## Build and sign

### The signing preimage

A first-party `PQ1` credential signs:

```text
from(32) || to(32) || amount(8 BE) || gas_limit(8 BE) || nonce(8 BE) ||
source_shard(4 BE) || target_shard(4 BE) ||
"PAYLOAD" || u32_be(len(bincode(Vec<OpCode>))) || bincode(Vec<OpCode>) ||
["PRIORITY" || priority(8 BE)]                 (only if priority != 0) ||
"CHAIN_ID" || chain_id(8 BE)                   (only if bound)
```

The `payload` is committed **inside** the signature, so it cannot be swapped
after signing. `TxBuilder` produces exactly this layout and the parity suite
compares it with `Transaction::base_signing_message`.

### Builders

| Builder | Payload |
| --- | --- |
| `TxBuilder::transfer(to, amount)` | empty (native value transfer) |
| `TxBuilder::contract_call(contract, method, args, value)` | `SysCallCallContractArgs` |
| `TxBuilder::stake(validator, amount)` | `SysCallStake` |
| `TxBuilder::unjail(validator, top_up)` | optional `SysCallStake` + `SysCallUnjail` |
| `TxBuilder::gov_propose(id, title, action, height)` | `SysCallGovPropose` |
| `TxBuilder::gov_vote(id, choice, height)` | `SysCallGovVote` |
| `EvmBindingBuilder::new(identity, evm, proof)?` | `SysCallBindEvmAddress` |
| `EvmCarrierBuilder::new(identity, raw_evm_tx, to_pq)?` | `SysCallEvmCarrier` |

Every builder is **chain-bound by default** and runs the protocol/fork guard
before it signs. Chainable setters:

```rust
let signed = TxBuilder::transfer([0x22; 32], 1_000_000)
    .nonce(7)
    .chain_id(5757)
    .base_fee(280_000)
    .priority_fee_per_gas(0)
    .shards(0, 0)          // source, target
    .implicit()            // omit the public key from the envelope
    .sign(&key)?;

signed.verify()?;
println!("{}", signed.tx_hash_hex());
```

`unbound()` exists for tests only and prints a warning. Do not ship it.

### Envelope

Explicit (activation) envelope — carries the public key and pays the
`45_000` gas activation surcharge:

```text
"PQ1" | scheme=0x02 | 0x00 | pk_len(2 LE) | pubkey(897) | salt(16) |
sig_len(2 LE) | signature(666) | [chain_id(8 BE)]
```

Implicit envelope — public key omitted, no surcharge:

```text
"PQ1" | 0x02 | 0x01 | 0x0000 | sig_len(2 LE) | signature(666) | [chain_id(8 BE)]
```

Use `.implicit()` once the account's key is already known on chain. Use the
explicit form for the first transaction from a fresh account.

## The fee rule

Admission is one comparison:

```text
gas_limit >= base_fee
           + failure_penalty(from)
           + (45_000 if explicit PQ1)
           + priority_fee_per_gas
```

The balance check is slightly stricter:

```text
amount + gas_limit + (45_000 if explicit) <= balance
```

`base_fee` is a **static gas-unit floor**, not a dynamic fee market. The frozen
minimum is `280_000`. `stell_baseFee` serves the node's current admission
floor. The builder's default is:

```text
gas_limit = max(opcode_gas, base_fee) + (45_000 if explicit) + priority
```

For the node's exact answer **including the sender's failure penalty**, call
`stell_estimateFee` with the signed transaction:

```rust
let estimate = wallet.rpc().estimate_fee(&signed)?;
println!("{} nano-STELL for {} gas", estimate.estimated_fee, estimate.gas_limit);
```

## Wallet: build, submit, wait

```rust
use stellereum_sdk::prelude::*;

let key = FalconKeypair::load_key_file(std::path::Path::new("wallet.json"))?;
let mut wallet = Wallet::connect(key, "http://127.0.0.1:8545")
    .with_chain_id(5757);

// Nonce, chain id and the current base floor are filled in.
let signed = wallet.transfer([0x22; 32], 1_000_000)?;
signed.verify()?;

// Retries resend the SAME signed bytes; they never touch the signer or nonce.
let outcome = wallet.submit(&signed, &RetryPolicy::default())?;

let receipt = wallet.rpc().wait_for_receipt(
    &outcome.tx_hash,
    std::time::Duration::from_secs(60),
    std::time::Duration::from_secs(1),
)?;
println!("height {} status {}", receipt.height, receipt.status);
```

The nonce is the account's committed nonce from `stell_getBalance`. `Wallet`
caches it and advances it only after a successful submission. A retry resends
one already-signed `SignedTx`; a signature, fee or nonce refusal is returned
immediately. `rejected: transaction already in mempool` is treated as success.

### Read helpers

```rust
let account   = rpc.account(&addr)?;              // stell_getBalance
let nonce     = rpc.nonce(&addr)?;
let floor     = rpc.base_fee()?;                  // stell_baseFee
let validators = rpc.validators()?;               // stell_getValidators
let head      = rpc.block_number()?;              // stell_blockNumber
let block     = rpc.block(head)?;                 // stell_getBlock
let status    = rpc.transaction_status(&hash)?;   // stell_getTransactionStatus
let receipt   = rpc.receipt(&hash)?;              // stell_getTransactionReceipt
```

## Chain/fork guard

The node identifies a consensus ruleset with `FORK_ID`, a compile-time
FNV-1a-32 fold over the chain id, the ruleset/domain versions, the consensus
wire domains and the bound/round/height constants. A peer with a different fork
id cannot participate, and a transaction bound to another chain id is refused.

Both SDKs mirror the identity and run the **same check before signing**:

```rust
use stellereum_sdk::{ProtocolIdentity, SdkError, TxBuilder, FORK_ID};

let identity = ProtocolIdentity::local();
assert_eq!(identity.fork_id, FORK_ID);

// SdkError::ChainIdMismatch { expected: 5757, got: 1 }
let _ = TxBuilder::transfer([0x22; 32], 1).chain_id(1).sign(&key);

// SdkError::ForkIdMismatch { expected, got }
let mut stale = identity;
stale.fork_id ^= 1;
let _ = TxBuilder::transfer([0x22; 32], 1).identity(stale).sign(&key);
```

The current build is **protocol 1.0, consensus Ruleset v7, fork id
`0x3ae00ebc`** on chain id `5757`. A consensus-rule change moves the id; the
parity suite compares every folded constant and the derivation result against
the node, so a stale SDK fails its own tests.

::: warning Documentation drift
`docs/SDK.md` and `stellereum-sdk/README.md` still name ruleset v5/v6 and older
fork ids (`0x9d59096b`, `0x0f584a46`). The code and the TypeScript test vector
are authoritative: **Ruleset v7, fork id `0x3ae00ebc`**.
:::

## Governance builders

`SysCallGovPropose` / `SysCallGovVote` ride ordinary transactions. The sender
is the proposer/voter; the opcode never names an identity.

```rust
use stellereum_sdk::{GovAction, TxBuilder, VoteChoice};

let propose = TxBuilder::gov_propose(
    4,                                  // MUST equal governance.next_id
    "raise the floor".into(),
    GovAction::SetMinGasLimit(300_000),
    99,                                 // MUST equal the applying block height
)?
.nonce(pq_nonce)
.sign(&key)?;

let vote = TxBuilder::gov_vote(4, VoteChoice::Yes, 99)
    .nonce(next_nonce)
    .sign(&key)?;
```

Both are self-addressed and move no tokens. `GovAction` mirrors every node
variant and its bincode ordinal; `action.validate()` mirrors the node's
fail-fast bounds. The node re-validates at apply.

::: tip Proposal ids and heights are not hints
`proposal_id` must equal the governance `next_id` and `height_observed` must
equal the block height that applies the transaction. A mismatch is refused;
read `stell_governanceParams` and `stell_blockNumber` immediately before
building. See [`stellereum gov`](/nodes/validator#stellereum-gov-reference).
:::

## EVM binding and carrier

An EVM address may not be first-claimed by a PQ key that does not control it.
The claim carries **both** signatures:

1. Falcon-512 by the claiming PQ key over
   `keccak256("STELL_EVM_BIND_V1" ‖ chain_id_be(8) ‖ evm(20) ‖ pq(32))`;
2. a 65-byte secp256k1 proof of possession `r(32) ‖ s(32) ‖ recovery_id(1)`
   (EIP-2 low-s) over the same digest, whose recovered address must equal the
   EVM address being bound.

```rust
use stellereum_sdk::{EvmBindingBuilder, ProtocolIdentity};

let signed = EvmBindingBuilder::new(
    ProtocolIdentity::local(),
    evm_address,        // [u8; 20]
    evm_proof,          // exactly 65 bytes
)?
.nonce(pq_nonce)
.gas_limit(700_000)
.sign(&key)?;
```

The builder refuses a missing or malformed proof
(`SdkError::MissingEvmProof`), a proof that recovers another address
(`EvmProofMismatch`) and a claim bound to a foreign chain
(`EvmChainIdMismatch`).

The **carrier** is a normal `PQ1` transaction whose payload is
`SysCallEvmCarrier { chain_id, evm_tx, evm_address, pq_pubkey, evm_signature }`.
It settles an EVM value transfer under a bound PQ account:

```rust
use stellereum_sdk::{EvmCarrierBuilder, ProtocolIdentity};

let signed = EvmCarrierBuilder::new(
    ProtocolIdentity::local(),
    raw_evm_tx,   // canonical EIP-155 / EIP-1559 bytes
    recipient_pq, // [u8; 32]
)?
.nonce(declared_nonce)          // CarrierNonceMismatch
.amount_nano(declared_amount)   // CarrierValueMismatch
.gas_limit(900_000)
.sign(&key)?;
```

Limits:

- binding is **first-committed-wins**; the registry is a deterministic replay
  index, not a state-root domain, and the SDK cannot re-bind or unbind;
- the carrier is a **value transfer only**. There is no EVM interpreter and no
  EVM state trie, so contract creation and calldata are refused;
- the EVM secp256k1 signature is advisory for routing; the consensus
  credential is the `PQ1` envelope.

## RemoteSigner

The SDK crate itself has **no** `RemoteSigner`. The remote-signing seam is a
**node** module (`stellereum/src/remote_signer.rs`) for validator consensus
keys. It is documented here because operators integrating the SDK often look
for it.

There are two generations:

| Type | Key | Protocol | Use |
| --- | --- | --- | --- |
| `RemoteSigner` | Ed25519 | `GET {base}{public_key_path}`, `POST {base}{sign_path}` with `{"message":"<hex>"}` → `{"signature":"<128 hex>"}` | legacy Ed25519 vote half |
| `RemotePqSigner` | Falcon-512 | `/v2/public_key` + `/v2/sign` typed `ConsensusSignRequest` | full-PQ consensus |

`RemotePqSigner` is selected by `STELL_REMOTE_SIGNER_URL` (optional
`STELL_REMOTE_SIGNER_TOKEN`). It resolves the public key **once at startup**,
validates scheme `Falcon512`, the `0x09` header, the expected validator id and
(optionally) the committed public key, then pins it. Every returned signature
is verified against that pinned key. There is **no local fallback**: an
unreachable or refusing signer makes the node stop voting.

```bash
export STELL_REMOTE_SIGNER_URL=https://signer.internal:8443
export STELL_REMOTE_SIGNER_TOKEN=...   # prefer mutual TLS where supported
stellereum run --config node.yaml --shard 0
```

`HttpSignerTransport` defaults to a timeout, no redirects, no proxy
auto-discovery and a response-size cap; bearer-token auth is a convenience,
not a defense. Put the signer on a dedicated network segment, require mutual
TLS and restrict it to signing consensus vote messages. A compromised node can
otherwise use it as a signing oracle.

## Session grants

`SessionGrant` mints an `SF1` authorization for a delegated Falcon key:

```rust
use stellereum_sdk::{SessionGrant, TxBuilder, SCOPE_TRANSFER};

let grant = SessionGrant::new(
    &master_key,
    session_key.public_key(),
    valid_until,       // unix seconds
    max_gas_spend,     // cumulative gas budget
    SCOPE_TRANSFER,
    max_value_per_tx,
    5757,
)?;
grant.verify_master();

let signed = TxBuilder::transfer([0x22; 32], 1_000)
    .nonce(master_nonce)
    .sign_with_session(&session_key, &grant)?;
```

`tx.from` is the **master** address; nonce, balance and fee belong to the
master. See [Session keys](/sdk/session-keys) for the full grant and
revocation model.

## Limits

| Not supported | Why / what to do instead |
| --- | --- |
| Native Falcon signing in JavaScript | No WASM binding in-tree. Use the Rust CLI/subprocess or HTTP helper. |
| EVM contract execution | No EVM interpreter or state trie. Carrier is a value transfer only. |
| EVM account / `eth_sendTransaction` / `eth_sign` | No secp256k1 account. Use `stell_sendRawTransaction` with a PQ envelope. |
| EVM binding as consensus state | Node-local replay index, first-committed-wins. A stale index can under-report, never fork value. |
| `eth_subscribe` / JSON-RPC batching (JS) | Refused / not implemented. Use `stell_subscribe` on the WS/SSE transports. |
| STS tokens, orderbook, bridge, price feeds, session publish/revoke, claim rewards, key rotation, delegate/unbond | Real opcodes, outside the wallet shapes. Use the node CLI or extend the SDK with a parity-tested encoder. |
| Paymaster / sponsored transactions | Not minted by this crate; the node accepts `SP1` envelopes on a PQ1 inner. Use the node crate's `Transaction::sign_with_sponsor_falcon512`. |
| Dynamic fee market / replacement-by-fee | `base_fee` is a static floor. Priority is an explicit signed bid. |
| Automatic nonce-gap filling | The SDK returns the node's gap error; it will not invent transactions. |
| SPV proof verification | The RPC client exposes answers; use `stellereum light-client` for a real verifier. |
| Encrypted keystore / hardware wallet / multisig | Plaintext JSON `0600`; no HSM/MPC. Node-side remote signing exists for validators only. |

## Common errors

| Node answer (`-32000` unless noted) | Meaning / fix |
| --- | --- |
| `Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope` | Signature blob is not a `PQ1`/`SF1` envelope. Sign with Falcon. |
| `invalid transaction signature` | Wrong key, nonce, chain, fee preimage or framing. Rebuild and sign; do not patch bytes. |
| `rejected: offered fee is below the base fee` | Raise `gas_limit` to `required_fee_for_tx`; use `stell_estimateFee`. |
| `rejected: sender cannot pay amount + gas_limit` | Fund `amount + gas_limit + 45_000` (explicit). |
| `rejected: nonce gap: sender can execute X, got Y (fill the gap first)` | Send the missing nonce first, then re-sign. |
| `rejected: transaction already in mempool` | Success for submission: the exact transaction is pooled. |
| `rejected: unbound transaction refused ...` | Bind to the node's chain id. |
| `Transaction chain_id mismatch: ...` | You signed for another chain. Re-sign bound to this one. |
| `-32602` / `bad hex` / `decode: ...` | Malformed params or wire bytes; rebuild from the SDK. |

`SdkError` maps nonce-gap and insufficient-balance strings to typed variants;
everything else carries the node's code, message and data.

## Verification suite

`cargo test --features node-parity` checks, against the node's own types:

- `verify_pq_signature` accepts the SDK signature and `derive_pq_address`
  equals the SDK address;
- `bincode(Transaction)` decodes into the node's `Transaction` and
  `verify_signature()` passes;
- explicit, implicit, unbound and priority-bid envelopes;
- stake / unjail / contract-call payloads equal the node's `bincode(OpCode)`;
- calldata equals `ContractAbi::encode_args`;
- `SF1` grants decode into `SessionKeyAuthorization` and both verifiers pass;
- transaction hashes equal `compute_tx_hash`;
- every fork-id fold and the derived id equal the node's;
- EVM binding/carrier preimages and governance payloads equal the node's;
- fixed vectors are embedded in `sdk-js/test` so the TypeScript encoders
  cannot drift silently;
- retry tests assert identical bytes and nonce.

## Next

Continue with the [TypeScript SDK](/sdk/typescript) for the browser-facing client, then [Wallet signing](/sdk/wallets-and-signing) and [Session keys](/sdk/session-keys) for delegated authority.
