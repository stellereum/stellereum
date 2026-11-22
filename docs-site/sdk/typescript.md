---
title: TypeScript SDK
description: "@stellereum/sdk — EIP-1193 reads, buildAndSign, protocol guard and governance/EVM builders."
outline: deep
---

# TypeScript SDK (`@stellereum/sdk`)

`@stellereum/sdk` is the JavaScript client for wallets and dApps that need to read chain state, build a transaction, and hand Falcon signing to a trusted Rust process. It is a thin client: it does not implement Falcon, BLAKE3 or EVM execution in JavaScript.

The package provides:

- **`StellereumProvider`** — EIP-1193-style, **read-only** provider. `eth_*`
  reads and `stell_*` methods pass through to the node; EVM signing and write
  methods throw `UnsupportedMethodError` (`4200`).
- **`StellereumClient`** — typed reads, `buildAndSign`, submission retries
  that resend the same raw bytes, and receipt waiting.
- **`SubprocessFalconSigner` / `HttpFalconSigner`** — real Falcon-512 signing in
  the Rust process. JavaScript never sees the key.

::: warning JavaScript does not sign Falcon here
There is no WASM Falcon binding in this repository. Falcon-512 signing needs
the FIPS 206 discrete-Gaussian sampler over the private NTRU basis; the only
audited implementation in-tree is the Rust one. `buildAndSign` therefore
delegates to `stellereum-sdk-cli sign` (subprocess) or
`stellereum-sdk-cli serve` (localhost HTTP helper).
:::

## Install and build

```bash
cd sdk-js
npm install
npm test             # node --test test/*.test.ts
npm run typecheck    # tsc --noEmit
npm run build        # tsc -> dist/
```

Requirements: **Node >= 22.6** (tests run `.ts` directly through type
stripping) and the Rust `stellereum-sdk-cli` on `PATH`, or an explicit
`command`/`args`.

The package is in-tree at `sdk-js/`; import it by path or workspace link until
a registry release is published.

## Read-only provider

```ts
import { StellereumProvider } from "@stellereum/sdk";

const provider = new StellereumProvider({ url: "http://127.0.0.1:8545" });

await provider.chainId();          // 5757, from eth_chainId
await provider.blockNumber();      // number
await provider.getBalance("0x...");
await provider.stellAccount("22".repeat(32)); // { balance, nonce }
await provider.stellValidators();
await provider.stellBaseFee();
```

`request({ method, params })` forwards only methods whose name starts with
`eth_`, `stell_`, `net_` or `web3_`. It answers `[]` for
`eth_accounts` / `eth_requestAccounts`, `null` for `eth_coinbase`, and throws
`UnsupportedMethodError` for every EVM write:

```text
eth_sendTransaction     eth_sendRawTransaction   eth_sign
eth_signTransaction     eth_signTypedData*       personal_*
wallet_addEthereumChain wallet_switchEthereumChain
wallet_watchAsset       wallet_sendCalls         wallet_getCapabilities
```

::: tip Why EVM writes are blocked locally
A secp256k1 signature is never a consensus credential on Stellereum. The
honest replacement is `stell_sendRawTransaction` with a `PQ1` envelope (or an
EVM binding + carrier). Blocking `eth_sendRawTransaction` in the provider
avoids a misleading MetaMask path that the node would refuse anyway.
:::

Provider events (`on`, `once`, `removeListener`, `emit`) are a local
EIP-1193-shaped convenience only. **No polling is performed** and there is no
`eth_subscription` transport. For push updates use `stell_subscribe` over the
node WebSocket/SSE transports; see [WebSocket and SSE](/api/websocket-sse).

## Client: reads, buildAndSign, submit, wait

```ts
import {
  StellereumClient,
  SubprocessFalconSigner,
} from "@stellereum/sdk";

const signer = new SubprocessFalconSigner({
  command: "stellereum-sdk-cli",
  keyPath: "/home/me/wallet.json",
});

const client = new StellereumClient({
  url: "http://127.0.0.1:8545",
  signer,
  address: "22".repeat(32), // optional when the signer exposes it
});

const signed = await client.transfer("33".repeat(32), 1_000_000);
console.log(signed.rawTransaction, signed.hash);

const { submit, receipt } = await client.sendAndWait(signed);
console.log(submit.hash, submit.attempts, receipt.status);
```

`buildAndSign` fills the nonce (`stell_getBalance`), chain id
(`stell_chainId`) and current base floor (`stell_baseFee`) before signing. The
Rust signer computes the final `gas_limit`:

```text
max(opcode_gas, base_fee) + 45_000 (explicit PQ1) + priority
```

| Client method | RPC |
| --- | --- |
| `chainId()` | `stell_chainId` |
| `account(address?)` | `stell_getBalance` |
| `nonce(address?)` | `stell_getBalance` |
| `baseFee()` | `stell_baseFee` |
| `blockNumber()` | `stell_blockNumber` |
| `block(height)` | `stell_getBlock` |
| `validators()` | `stell_getValidators` |
| `receipt(hash)` | `stell_getTransactionReceipt` (`null` while pending/unknown) |
| `estimateFee(rawTransaction)` | `stell_estimateFee` |
| `transfer` / `contractCall` / `stake` / `unjail` | build intent → signer |
| `sendSigned` / `sendAndWait` | `stell_sendRawTransaction` |
| `waitForReceipt` | polls `stell_getTransactionReceipt` |

### Retry contract

`sendSigned` retries **transport failures** and **retryable RPC errors** with
exponential backoff (default 4 attempts, 200 ms base, 2 s cap). It treats
`rejected: transaction already in mempool` as success and returns the local
hash. Every other refusal is returned immediately. Retries resend the **same**
`rawTransaction`; they never re-sign or advance the nonce.

## Signers

### Subprocess

```ts
const signer = new SubprocessFalconSigner({
  command: "stellereum-sdk-cli",
  keyPath: "/tmp/wallet.json",
  // args?: string[]
});
```

The intent is written to the CLI's stdin as JSON. The signed `PQ1` bytes and
metadata come back on stdout. No key material crosses into JavaScript.

### HTTP helper

```ts
import { HttpFalconSigner } from "@stellereum/sdk";

const signer = new HttpFalconSigner({
  url: "http://127.0.0.1:8787",
  token: process.env.STELL_SDK_SIGNER_TOKEN,
});
```

Start the helper with:

```bash
stellereum-sdk-cli serve --key /tmp/wallet.json --listen 127.0.0.1:8787
```

`serve` is plain HTTP on loopback. Set `STELL_SDK_SIGNER_TOKEN` to require
`Authorization: Bearer <token>`. Keep it on localhost and treat the token as a
credential.

### Signer protocol

Both transports speak the same JSON:

```json
{
  "tx": {
    "kind": "transfer",
    "to": "Stl57... or 64-hex",
    "amount": 1000,
    "nonce": 7,
    "chain_id": 5757,
    "base_fee": 280000,
    "priority_fee_per_gas": 0,
    "implicit": false
  }
}
```

```json
{
  "ok": true,
  "tx_hex": "...",
  "tx_hash": "...",
  "from": "...",
  "from_stl57": "Stl57...",
  "nonce": 7,
  "chain_id": 5757,
  "gas_limit": 325000,
  "activation": true,
  "envelope": "pq1-explicit"
}
```

Supported `kind` values: `transfer`, `contract_call`, `stake`, `unjail`,
`evm_binding`, `evm_carrier`, `gov_propose`, `gov_vote`, `prepared`.

The Rust CLI also exposes:

```bash
stellereum-sdk-cli keygen --out wallet.json
stellereum-sdk-cli address --key wallet.json
stellereum-sdk-cli sign --key wallet.json < request.json
stellereum-sdk-cli sign-digest --key wallet.json --digest <32-byte-hex>
stellereum-sdk-cli serve --key wallet.json --listen 127.0.0.1:8787
```

`sign-digest` is what the `signDigest` hook uses for the inner EVM binding /
carrier statements.

## Protocol and fork guard

Every builder refuses a chain id or fork id that is not the configured node
identity. The check runs **before** any signature is requested.

```ts
import {
  FORK_ID_HEX,
  assertChainId,
  assertIdentity,
  localIdentity,
} from "@stellereum/sdk";

assertIdentity(localIdentity());        // throws ProtocolError
assertChainId(localIdentity(), 5757);   // throws ProtocolError
console.log(FORK_ID_HEX);               // "0x3ae00ebc"
```

`ProtocolError.code` is one of:

- `chain_id_mismatch`
- `fork_id_mismatch`
- `protocol_version_mismatch`
- `invalid_identity`

The current identity is **protocol 1.0, consensus Ruleset v7, fork id
`0x3ae00ebc`**, chain id `5757`. `client.identity()` returns the configured
identity; `localVersionInfo()` returns the same shape the node's
`version_info()` produces.

::: warning Documentation drift in the package README
`sdk-js/README.md` still says ruleset v5 / `0x9d59096b`. The source
(`src/protocol.ts`) and the test vector assert **Ruleset v7 / `0x3ae00ebc`**.
:::

## Unsigned builders

The package can build the bytes for shapes that need more than one signature,
then ask the Rust signer only for the envelope.

### Governance

```ts
import { buildGovPropose } from "@stellereum/sdk";

const unsigned = buildGovPropose({
  from,                 // 32-byte PQ address
  nonce: 6,
  gasLimit: 500_000,
  proposalId: 4,        // must equal governance.next_id
  title: "raise the floor",
  action: { type: "set_min_gas_limit", value: 300_000 },
  heightObserved: 99,   // must equal the applying block height
});

const signed = await client.signPrepared(unsigned);
await client.sendAndWait(signed);
```

```ts
import { buildGovVote } from "@stellereum/sdk";

const vote = buildGovVote({
  from, nonce: 7, proposalId: 4,
  choice: "yes", heightObserved: 101,
});
```

The convenience wrappers `client.govPropose(...)` and `client.govVote(...)`
fill the nonce, guard the chain/fork, build and sign in one call.

### EVM binding

`buildEvmBinding` requires the 65-byte secp256k1 proof of possession and a
Falcon signature over the binding digest.

```ts
import { buildEvmBinding, evmBindingDigest } from "@stellereum/sdk";

const digest = evmBindingDigest(5757, evmAddress, from);
const bindingSignature = await signer.signDigest!(digest);

const unsigned = buildEvmBinding({
  from,
  evmAddress,
  evmProof,              // 65-byte hex
  bindingSignature,      // 666-byte Falcon hex
  nonce,
  gasLimit: 700_000,
});
```

`client.evmBinding(...)` does the same and calls `signDigest` for you when the
signer exposes it. Without that hook you must pass `bindingSignature`
explicitly.

### EVM carrier

`buildEvmCarrier` decodes the EVM intent, takes the nonce/value from it, and
requires a Falcon signature over `keccak256(evmTx)`:

```ts
const { signed, plan } = await client.evmCarrier({
  evmTx: rawEvmTx,
  recipientPq,
  pqPublicKey,
  // optional pins: a mismatch throws BuilderError
  nonce,
  amountNano,
});
```

`BuilderError` codes:

| Code | Meaning |
| --- | --- |
| `invalid_argument` | wrong address/key length, bad title, missing `pqPublicKey` |
| `missing_evm_proof` | the 65-byte proof is absent |
| `missing_inner_signature` | `signDigest` is unavailable and no signature was supplied |
| `carrier_nonce_mismatch` | pinned nonce differs from the EVM intent |
| `carrier_value_mismatch` | pinned amount differs from the EVM intent |
| `invalid_evm_intent` | not a value transfer, malformed RLP, or unsupported chain |

### `UnsignedTransaction`

Every builder returns:

```ts
interface UnsignedTransaction {
  txHex: string;              // bincode(Transaction), NO envelope
  payloadHex: string;
  signingMessageHex: string;
  unsignedTxHash: string;
  from: string;
  to: string;
  nonce: number;
  chainId: number;
  gasLimit: number;
  // plus shape-specific fields
}
```

`client.signPrepared(unsigned)` asks the signer to attach the `PQ1` envelope.
The signer refuses an unsigned transaction whose `from` is not its own address.

## JavaScript limits

| Limit | Consequence |
| --- | --- |
| No native Falcon | `sign` / `signDigest` call the Rust sidecar. A third-party signer without `signDigest` must supply inner signatures explicitly. |
| No BLAKE3 | Deriving a PQ address needs BLAKE3. Pass `from` / `pqPublicKey` from the signer or node. |
| No secp256k1 recovery | JS decodes the EVM intent fields but cannot recover the EVM sender or verify the EVM signature. The node verifies over the same bytes. |
| No EVM account | `eth_accounts` is `[]`; signing methods throw `4200`. |
| No EVM execution | Carrier is a value transfer only. No calldata, no contract creation. |
| No JSON-RPC batching | One request per call. |
| No `eth_subscribe` | The node refuses it. `stell_subscribe` exists; this package does not implement its framing. |
| No node identity RPC | `client.identity()` is the configured/local identity; there is no `version_info` RPC yet. |
| Signer trust | The sidecar holds the key. Keep it on localhost. |

## Common errors

`RpcError` keeps `method`, `code`, `message` and `data`. `ProviderRpcError`
re-exposes the same in EIP-1193 shape. `TransportError` marks a network
failure; `isRetryableError` decides whether a retry is safe.

| Error | Meaning |
| --- | --- |
| `RpcError` `-32000` | Node refusal: fee, balance, nonce, signature, sponsor/session policy. Read the message. |
| `RpcError` `-32602` | Malformed params or wire bytes. Rebuild through the builders. |
| `UnsupportedMethodError` (`4200`) | The provider does not implement this EVM write. |
| `ProtocolError` | Chain/fork mismatch detected before signing. |
| `SignerError` | The Rust sidecar failed; the transaction was not signed. |
| `BuilderError` | The local builder refused the intent; nothing was sent. |

See [Errors](/api/errors) for the complete code map.

## Next

Continue with the [Rust SDK](/sdk/rust) for the canonical builders, or [Wallet signing](/sdk/wallets-and-signing) for message signatures. [Errors](/api/errors) maps every refusal code.
