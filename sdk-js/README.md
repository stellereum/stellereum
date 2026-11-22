# @stellereum/sdk

TypeScript dApp client for Stellereum: an EIP-1193-style **read** provider,
typed `stell_*`/`eth_*` helpers, `buildAndSign` with a real Falcon-512 signer
sidecar, a protocol/fork guard, and unsigned EVM/governance builders.

[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange)](../stellereum-sdk/LICENSE)
[![Version](https://img.shields.io/badge/version-0.3.0-blue)](package.json)
[![Node](https://img.shields.io/badge/node-%3E%3D22.6-brightgreen)](package.json)
[![Network](https://img.shields.io/badge/network-testnet-yellow)](https://docs.stellereum.org/get-started/networks)
[![Audit](https://img.shields.io/badge/audit-none%20yet-red)](https://docs.stellereum.org/security/status)

## What it is / what it is not

- **Is** a client for reads, transaction intents, PQ submission, receipt
  waiting, and the node's EVM-binding/carrier and governance transaction
  shapes.
- **Is not** a Falcon-512 implementation. JavaScript never signs Falcon here;
  `buildAndSign` delegates the signature to the Rust
  [`stellereum-sdk-cli`](../stellereum-sdk/README.md) binary (subprocess or
  loopback HTTP).
- **Is not** an EVM wallet. It never holds a secp256k1 account, returns `[]`
  for `eth_accounts`, and refuses EVM signing/write methods locally with
  `UnsupportedMethodError` (code `4200`).
- **Is not** an EVM execution client. The EVM carrier settles a value transfer
  only; there is no calldata, contract creation, or EVM state.
- **Is not** a subscription transport, batch client, or address-derivation
  library. It has no WebSocket/`eth_subscription` support, no JSON-RPC
  batching, and no BLAKE3 address derivation (pass `from`/`pqPublicKey`).

## Install and build

```bash
cd sdk-js

npm install
npm run typecheck       # tsc --noEmit
npm test                # node --test test/*.test.ts
npm run build           # tsc -> dist/
```

Requirements:

- **Node >= 22.6** — the test script runs TypeScript directly through Node's
  type stripping. Use a current Node 22.x or newer; the declared engine floor is
  the package minimum, not a promise that every 22.6.x patch has type stripping
  enabled by default.
- The Rust signing CLI on `PATH`, or an explicit `command`/`args`:

```bash
cd ../stellereum-sdk
cargo install --path .
stellereum-sdk-cli version
```

The package entry point is `dist/index.js` (`main`/`exports`), so run
`npm run build` before importing `@stellereum/sdk` as a package. This tree is
consumed by path or workspace link until a registry release is published:

```json
{
  "dependencies": {
    "@stellereum/sdk": "file:../sdk-js"
  }
}
```

## Quickstart

Start a node on `127.0.0.1:8545`, create and fund a key, and install the CLI as
shown above. Then:

```ts
import {
  StellereumClient,
  StellereumProvider,
  SubprocessFalconSigner,
} from "@stellereum/sdk";

const RPC = "http://127.0.0.1:8545";

// Read-only EIP-1193 surface.
const provider = new StellereumProvider({ url: RPC });
console.log(await provider.chainId());        // 5757
console.log(await provider.blockNumber());
console.log(await provider.stellValidators());

// The signer runs in the Rust process; the key never enters JavaScript.
const PQ_ADDRESS = "22".repeat(32);           // output of `stellereum-sdk-cli address`
const signer = new SubprocessFalconSigner({
  command: "stellereum-sdk-cli",
  keyPath: "/home/me/wallet.json",
  address: PQ_ADDRESS,
});

const client = new StellereumClient({ url: RPC, signer, address: PQ_ADDRESS });
const signed = await client.transfer("33".repeat(32), 1_000_000);

console.log(signed.rawTransaction, signed.hash);
const { submit, receipt } = await client.sendAndWait(signed);
console.log(submit.hash, submit.attempts, receipt.status);
```

`buildAndSign` fills the nonce (`stell_getBalance`), chain id
(`stell_chainId`), and current base floor (`stell_baseFee`) before handing the
intent to the signer. The Rust signer computes the final `gas_limit`:

```text
max(opcode_gas, base_fee) + 45_000 (explicit PQ1) + priority
```

If you do not pass `address`, the client uses `signer.address`; without either,
nonce lookup fails with an explicit error.

## API surface

### Provider and client

| API | Description |
| --- | --- |
| `new StellereumProvider({ url, fetch?, headers?, timeoutMs? })` | EIP-1193-style read provider. |
| `provider.request({ method, params })` | Forward `eth_*`/`stell_*`/`net_*`/`web3_*` methods; refuse EVM signing/write methods. |
| `provider.chainId/chainIdHex/blockNumber` | `eth_chainId` / `eth_blockNumber`. |
| `provider.getBalance/getNonce/getCode/call/getReceipt` | Standard `eth_*` reads. |
| `provider.stellChainId/stellAccount/stellNonce` | `stell_*` account reads. |
| `provider.stellReceipt/stellBlock/stellValidators/stellBaseFee` | `stell_*` chain reads. |
| `provider.on/once/removeListener/emit` | Local EIP-1193-shaped events; no polling or subscription transport. |
| `new StellereumClient({ url, signer, address?, identity?, fetch?, headers?, timeoutMs? })` | Client with signing and submission. |
| `client.chainId/account/nonce/baseFee/blockNumber/block/validators` | Typed reads. |
| `client.receipt(hash)` | Receipt, or `null` while pending/unknown. |
| `client.estimateFee(rawTransaction)` | `stell_estimateFee`. |
| `client.buildAndSign(intent, options?)` | Fill nonce/chain/fee, then ask the signer for the envelope. |
| `client.transfer/contractCall/stake/unjail` | Convenience intent wrappers. |
| `client.signPrepared(unsigned)` | Attach a `PQ1` envelope to bytes from a builder. |
| `client.evmBinding/evmCarrier` | Build and sign EVM registry/carrier shapes; the caller submits them. |
| `client.govPropose/govVote` | Build and sign governance shapes; the caller submits them. |
| `client.identity()/address()` | Configured identity and sender address. |
| `client.sendSigned/sendAndWait` | Submit with retries; retries resend the same raw bytes. |
| `client.waitForReceipt(hash, { timeoutMs?, pollMs? })` | Poll `stell_getTransactionReceipt`. |

### Builders, protocol and signers

| API | Description |
| --- | --- |
| `buildGovPropose/buildGovVote` | Unsigned self-addressed governance transactions. |
| `buildEvmBinding` | Unsigned `SysCallBindEvmAddress`; requires the 65-byte proof and a Falcon binding signature. |
| `buildEvmCarrier` | Unsigned `SysCallEvmCarrier`; decodes the EVM intent and pins nonce/value. |
| `evmBindingDigest/evmCarrierDigest` | The inner Falcon digests for those two shapes. |
| `localIdentity/assertIdentity/assertChainId/assertIdentityForChain` | Protocol and fork guard. |
| `FORK_ID/FORK_ID_HEX/CONSENSUS_RULESET_VERSION` | Ruleset v7 identity constants (`FORK_ID_HEX === "0x3ae00ebc"`). |
| `SubprocessFalconSigner` | Runs `stellereum-sdk-cli sign --key …` once per signature. |
| `HttpFalconSigner` | POSTs the same JSON to `stellereum-sdk-cli serve`. |
| `ProtocolError` | `chain_id_mismatch`, `fork_id_mismatch`, `protocol_version_mismatch`, `invalid_identity`. |
| `BuilderError` | `invalid_argument`, `missing_evm_proof`, `missing_inner_signature`, `carrier_nonce_mismatch`, `carrier_value_mismatch`, `invalid_evm_intent`. |

The current guard identity is protocol `1.0`, consensus ruleset v7, fork id
`0x3ae00ebc`, chain id `5757`. `client.identity()` is the configured/local
identity; the package does not fetch the node's identity over RPC.

### Signer protocol

Both signer transports speak the same JSON. Request:

```json
{
  "tx": {
    "kind": "transfer",
    "to": "Stl57... or 64-hex",
    "amount": 1000,
    "nonce": 7,
    "chain_id": 5757,
    "base_fee": 280000,
    "priority_fee_per_gas": 0
  }
}
```

Response:

```json
{
  "ok": true,
  "tx_hex": "...",
  "tx_hash": "...",
  "from": "...",
  "from_stl57": "Stl57...",
  "to": "...",
  "nonce": 7,
  "chain_id": 5757,
  "gas_limit": 325000,
  "activation": true,
  "envelope": "pq1-explicit"
}
```

Supported `kind` values: `transfer`, `contract_call`, `stake`, `unjail`,
`evm_binding`, `evm_carrier`, `gov_propose`, `gov_vote`, `prepared`.

Start the HTTP helper with:

```bash
stellereum-sdk-cli serve --key /home/me/wallet.json --listen 127.0.0.1:8787
```

Set `STELL_SDK_SIGNER_TOKEN` on the helper to require
`Authorization: Bearer <token>`; pass the same token to `HttpFalconSigner`.
The helper is plain HTTP on loopback.

## Configuration

| Option | Default | Description |
| --- | --- | --- |
| Provider/client `url` | `http://127.0.0.1:8545` | Node JSON-RPC endpoint. |
| `timeoutMs` (RPC) | `15_000` | Per-request fetch timeout. |
| `headers` | `{}` | Extra HTTP headers for the RPC client. |
| `fetch` | platform `fetch` | Injectable fetch implementation (tests/proxies). |
| Client `address` | `signer.address` | Sender for nonce lookup. |
| Client `identity` | `localIdentity()` | Protocol/fork guard identity. |
| `SubprocessFalconSigner.command` | `stellereum-sdk-cli` | Signer binary. |
| `SubprocessFalconSigner.keyPath` | required unless `args` supplied | Key file passed as `sign --key`. |
| `SubprocessFalconSigner.args` | `["sign","--key",keyPath]` | Override the CLI arguments. |
| `SubprocessFalconSigner.timeoutMs` | `30_000` | Kill a hung signer. |
| `HttpFalconSigner.url` | required | Loopback `serve` URL. |
| `HttpFalconSigner.token` | unset | Bearer token for the helper. |
| `STELL_SDK_SIGNER_TOKEN` | unset | Read by the CLI helper, not by this package; pass it explicitly to `HttpFalconSigner`. |

Node.js `>= 22.6` is required for the test/build toolchain.

## Testing

```bash
cd sdk-js
npm test
npm run typecheck
npm run build
```

`npm test` is `node --test test/*.test.ts`. The suite uses injected fetch and a
fake signer; it does not need a running node. It is an independent process and
does not use the node crate's serial-lib wrapper; it can run alongside the Rust
workspace suites.

## Documentation

- [TypeScript SDK guide](https://docs.stellereum.org/sdk/typescript)
- [Rust SDK and signer](https://docs.stellereum.org/sdk/rust)
- [JSON-RPC reference](https://docs.stellereum.org/api/json-rpc)
- [WebSocket and SSE](https://docs.stellereum.org/api/websocket-sse)
- [Security status](https://docs.stellereum.org/security/status)
- [Security policy](../SECURITY.md)
- [License](../stellereum-sdk/LICENSE) — MIT OR Apache-2.0
  ([MIT](../stellereum-sdk/LICENSE-MIT),
  [Apache-2.0](../stellereum-sdk/LICENSE-APACHE))

## Status

Testnet only. No external audit. The package does not sign Falcon in
JavaScript and depends on a trusted Rust signer process that holds the key.
Keep that signer on localhost and do not expose it to untrusted callers.

Open work before production use: an external audit; a published package; and,
only if a vetted implementation appears, an in-process Falcon signer. Until
then, `buildAndSign` always crosses the Rust boundary.
