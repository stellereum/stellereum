# @stellereum/sdk (TypeScript)

Stellereum dApp client:

- **`StellereumProvider`** — EIP-1193-style, read-only provider. `eth_*` reads
  pass through to the node; `stell_*` methods pass through; EVM signing and
  write methods throw `UnsupportedMethodError` (4200).
- **`StellereumClient`** — typed reads, `buildAndSign`, submission retries
  that resend the same raw bytes, and receipt waiting.
- **`SubprocessFalconSigner` / `HttpFalconSigner`** — real Falcon-512 signing.

## Honest statement: JS does not sign Falcon natively here

There is no WASM Falcon binding in this repository. Falcon-512 signing needs
the FIPS 206 discrete-Gaussian sampler over the private NTRU basis; the only
audited implementation in the tree is the Rust one. This package therefore
delegates `buildAndSign` to:

1. `stellereum-sdk-cli sign --key wallet.json` (default, subprocess), or
2. `stellereum-sdk-cli serve --key wallet.json` (localhost HTTP helper).

The key never enters JavaScript; only the intent and the signed `PQ1` bytes
cross the process boundary. The Rust CLI must be on `PATH`, or pass
`command`/`args`.

## Quickstart

```ts
import {
  StellereumClient,
  StellereumProvider,
  SubprocessFalconSigner,
} from "@stellereum/sdk";

const rpcUrl = "http://127.0.0.1:8545";
const provider = new StellereumProvider({ url: rpcUrl });

console.log(await provider.chainId());          // 5757
console.log(await provider.stellValidators());

const signer = new SubprocessFalconSigner({
  command: "stellereum-sdk-cli",
  keyPath: "/home/me/wallet.json",
});
const client = new StellereumClient({ url: rpcUrl, signer });

const signed = await client.transfer("22".repeat(32), 1_000_000);
console.log(signed.rawTransaction, signed.hash);

const { submit, receipt } = await client.sendAndWait(signed);
console.log(submit.hash, receipt.status);
```

`buildAndSign` fills the nonce (`stell_getBalance`), chain id
(`stell_chainId`) and current base floor (`stell_baseFee`) before signing. The
Rust signer computes the final `gas_limit`:
`max(opcode_gas, base_fee) + 45_000 (explicit PQ1) + priority`.

## HTTP signer

```ts
import { HttpFalconSigner } from "@stellereum/sdk";

const signer = new HttpFalconSigner({
  url: "http://127.0.0.1:8787",
  token: process.env.STELL_SDK_SIGNER_TOKEN,
});
```

## Protocol guard and the new unsigned builders

Every new-shape builder refuses a chain id / fork id that is not the
configured node identity (`ProtocolError`, codes `chain_id_mismatch`,
`fork_id_mismatch`, `protocol_version_mismatch`). The current identity is
protocol 1.0, consensus ruleset v3, fork id `0xb13baff4`, chain 5757.

```ts
import { buildEvmCarrier, buildGovPropose } from "@stellereum/sdk";

const unsigned = buildGovPropose({
  from, nonce: 6, gasLimit: 500_000,
  proposalId: 4, title: "raise the floor",
  action: { type: "set_min_gas_limit", value: 300_000 },
  heightObserved: 99,
});
const signed = await client.signPrepared(unsigned);
```

`buildEvmBinding` requires the 65-byte secp256k1 proof of possession and a
Falcon binding signature; `buildEvmCarrier` requires a Falcon signature over
`keccak256(evmTx)` and takes the transaction nonce/value from the EVM intent
(passing `nonce`/`amountNano` pins them and a mismatch is refused). The inner
Falcon signatures come from the Rust sidecar (`signer.signDigest`, backed by
`stellereum-sdk-cli sign-digest`); without that hook, pass them explicitly.

Limits: JS never signs Falcon, never recovers the EVM sender and never
verifies the EVM signature (the node does, over the same bytes); address
derivation needs BLAKE3, so pass `from`/`pqPublicKey`. The carrier is a value
transfer only: no contract calls or calldata. EVM binding is
first-committed-wins.

## What is not supported

- No native Falcon signing in JS (see above).
- No EVM account: `eth_accounts` returns `[]`; signing/write methods throw.
- `eth_sendRawTransaction` is refused **locally** with 4200. The node also
  refuses the EVM write path (`stellereum/src/rpc/eth.rs:898-916`); the honest
  replacement is `stell_sendRawTransaction` with a PQ envelope.
- No EVM contract execution, no JSON-RPC batching, no wallet UI.
- No node RPC for the protocol identity yet; `client.identity()` is the
  configured/local identity.
- The signer is trusted with the key. Keep the CLI/helper on localhost.

## Commands

```bash
npm install
npm test                  # node --test test/*.test.ts (Node >= 22.6 type stripping)
npm run typecheck         # tsc --noEmit
npm run build             # tsc -> dist/ with .js imports
```
