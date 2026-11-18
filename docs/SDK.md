# Stellereum SDK

Client SDK for the live Stellereum chain:

- **Rust crate** [`stellereum-sdk/`](../stellereum-sdk): Falcon-512 keys,
  PQ1 transaction builder/signer, SF1 session grants, JSON-RPC client, wallet
  helpers, typed errors.
- **TypeScript package** [`sdk-js/`](../sdk-js): EIP-1193-style read
  provider, `stell_*`/`eth_*` read helpers, and `buildAndSign` delegated to
  the Rust Falcon signer.

> Testnet software. No external audit. The Rust key file is plaintext JSON at
> mode 0600; the JS package never sees the key (the signer process does).

---

## 1. Quickstart — Rust

```bash
cd stellereum-sdk
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

```rust
use stellereum_sdk::prelude::*;

fn main() -> Result<(), stellereum_sdk::SdkError> {
    // 1. Create or load a Falcon-512 key. The file is 0600 and plaintext.
    let key = FalconKeypair::generate()?;
    key.save_key_file(std::path::Path::new("wallet.json"))?;
    let key = FalconKeypair::load_key_file(std::path::Path::new("wallet.json"))?;
    println!("address {}", key.address_stl57());

    // 2. Bind the key to an RPC endpoint and the chain.
    let mut wallet = Wallet::connect(key, "http://127.0.0.1:8545")
        .with_chain_id(5757);

    // 3. Build + sign. Nonce, chain id and current base floor are filled in.
    let signed = wallet.transfer([0x22; 32], 1_000_000)?;
    println!(
        "tx {} nonce {} fee {}",
        signed.tx_hash_hex(),
        signed.nonce(),
        signed.gas_limit()
    );
    signed.verify()?;

    // 4. Submit the exact bytes; retries never re-sign.
    let outcome = wallet.submit(&signed, &RetryPolicy::default())?;
    println!("submitted {} after {} attempt(s)", outcome.tx_hash, outcome.attempts);

    // 5. Wait for a committed receipt.
    let receipt = wallet.rpc().wait_for_receipt(
        &outcome.tx_hash,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(1),
    )?;
    println!("height {} status {}", receipt.height, receipt.status);
    Ok(())
}
```

Using the builders directly:

```rust
use stellereum_sdk::{CallArg, SdkError, TxBuilder};

fn demo(key: &stellereum_sdk::FalconKeypair) -> Result<(), SdkError> {
    let call = TxBuilder::contract_call(
        [0x33; 32],
        "sum3",
        &[CallArg::U64(1), CallArg::U64(2), CallArg::U64(3)],
        0,
    )?;
    let _signed = call.nonce(7).chain_id(5757).sign(key)?;
    Ok(())
}
```

Read helpers:

```rust
fn demo(
    rpc: &stellereum_sdk::RpcClient,
    addr: &[u8; 32],
) -> Result<(), stellereum_sdk::SdkError> {
    let account = rpc.account(addr)?;            // stell_getBalance
    let _validators = rpc.validators()?;         // stell_getValidators
    let _block = rpc.block(rpc.block_number()?)?; // stell_getBlock
    let _status = rpc.transaction_status("aabb")?;
    let _ = account;
    Ok(())
}
```

CLI:

```bash
cargo run --bin stellereum-sdk-cli -- keygen --out /tmp/wallet.json
cargo run --bin stellereum-sdk-cli -- address --key /tmp/wallet.json
cargo run --bin stellereum-sdk-cli -- sign --key /tmp/wallet.json < /tmp/request.json
cargo run --bin stellereum-sdk-cli -- serve --key /tmp/wallet.json --listen 127.0.0.1:8787
```

`serve` is a loopback HTTP helper for the TypeScript package. It requires
`Authorization: Bearer <STELL_SDK_SIGNER_TOKEN>` when that env var is set.

---

## 2. Quickstart — TypeScript

```bash
cd sdk-js
npm install
npm test
npm run typecheck
npm run build
```

The package requires Node >= 22.6 (tests run `.ts` directly via type
stripping). The Rust CLI must be on `PATH` or passed explicitly.

```ts
import {
  StellereumProvider,
  StellereumClient,
  SubprocessFalconSigner,
} from "@stellereum/sdk";

const url = "http://127.0.0.1:8545";

// Read-only EIP-1193 provider: eth_* reads + all stell_* methods.
const provider = new StellereumProvider({ url });
console.log(await provider.chainId());        // 5757
console.log(await provider.stellValidators());

// Real Falcon signing happens in the Rust process.
const signer = new SubprocessFalconSigner({
  command: "stellereum-sdk-cli",
  keyPath: "/tmp/wallet.json",
});
const client = new StellereumClient({ url, signer });

const signed = await client.transfer("22".repeat(32), 1_000_000);
const { submit, receipt } = await client.sendAndWait(signed);
console.log(submit.hash, receipt.status);
```

### JavaScript honesty: no native Falcon signing

There is **no WASM Falcon binding in this repository**. Falcon-512 signing is
a FIPS 206 discrete-Gaussian sample over the private NTRU basis; the only
audited implementation in-tree is the Rust one. `buildAndSign` therefore calls
one of:

- `SubprocessFalconSigner` → `stellereum-sdk-cli sign --key ...` (stdin JSON),
- `HttpFalconSigner` → `POST /sign` to `stellereum-sdk-cli serve`.

Both return `tx_hex` containing a real `PQ1` (or `SF1`) envelope. The JS
package does not encode the transaction or the envelope itself; the Rust
signer is the single source of truth for bytes. That is deliberate: a second
JS encoder would be an unaudited fork of the consensus wire format.

---

## 3. Transaction lifecycle (build → sign → submit → receipt)

### 3.1 Keys and addresses

- A wallet key is Falcon-512. The address is
  `BLAKE3("STL_ADDR_V4" || 0x02 || pubkey(897) || salt(16))`
  (`stellereum/src/post_quantum.rs:111,117,262`).
- The public key is the FIPS 206 897-byte encoding, header `0x09`
  (`post_quantum.rs:2127`).
- Signatures are the padded 666-byte Falcon-512 encoding. The chain's
  canonical header is **`0x29`**, not PQClean's `0x39`
  (`post_quantum.rs:2162-2181`). The SDK normalises the header and verifies
  the result with the node in the parity suite.

`Stl57...` addresses are base58(`addr || BLAKE3 checksum`), exactly the node's
format (`stellereum/src/address.rs:57`).

### 3.2 Nonce

The next nonce is the account's committed nonce from `stell_getBalance`
(`stellereum/src/rpc/reads.rs:1404`). The node refuses a far-future nonce with
a nonce-gap error (`stellereum/src/rpc/writes.rs:767`; mempool message at
`stellereum/src/mempool.rs:465`).

`Wallet` caches the nonce and advances it only after a successful submission.
Retries resend one already-signed `SignedTx`; they never touch the signer or
the nonce. This is the "never re-signs a nonce" guarantee.

### 3.3 Signing preimage

For a first-party PQ1 transaction the credential signs:

```text
from(32) || to(32) || amount(8 BE) || gas_limit(8 BE) || nonce(8 BE) ||
source_shard(4 BE) || target_shard(4 BE) ||
"PAYLOAD" || u32_be(len(bincode(Vec<OpCode>))) || bincode(Vec<OpCode>) ||
["PRIORITY" || priority(8 BE)]                      (only if priority != 0) ||
"CHAIN_ID" || chain_id(8 BE)                        (only if bound)
```

Source: `Transaction::base_signing_message`
(`stellereum/src/sharding/transaction.rs:521-543`), payload commitment
(`:553-567`), priority commitment (`:547-552`), chain commitment
(`:637-641`), and signed-message assembly (`:1319-1376`).

The `Vec<OpCode>` bincode body is the `PAYLOAD` bytes: a `u64` element count
followed by each opcode. The SDK's opcode encodings are pinned by the parity
tests; the four shapes are `SysCallStake` (`svm.rs:548`),
`SysCallCallContractArgs` (`svm.rs:994`), `SysCallUnjail` (`svm.rs:1124`), and
an empty payload for a native transfer.

### 3.4 Envelope

Explicit (activation) envelope:

```text
"PQ1" | scheme=0x02 | 0x00 | pk_len(2 LE) | pubkey(897) | salt(16) |
sig_len(2 LE) | signature(666) | [chain_id(8 BE)]
```

Implicit envelope omits the pubkey and salt:

```text
"PQ1" | 0x02 | 0x01 | 0x0000 | sig_len(2 LE) | signature(666) | [chain_id(8 BE)]
```

Source: `PqSignatureEnvelope::encode`
(`stellereum/src/sharding/envelope.rs:106-137`) and strict decode (`:187`).
Only Falcon-512 (`0x02`) is live; the node refuses every other scheme id
(`stellereum/src/post_quantum.rs:188-206`).

The SDK constructs the same transaction with the node's own constructors in
the parity suite: `Transaction::new_pq_explicit` (`transaction.rs:950`),
`new_pq_implicit` (`:983`), `new_pq_explicit_with_chain` (`:1012`),
`new_pq_implicit_with_chain` (`:1050`).

### 3.5 Submit

`stell_sendRawTransaction` takes `{ "tx": "<hex of bincode(Transaction)>" }`
(`stellereum/src/rpc/writes.rs:695-751`). It:

1. decodes the bincode `Transaction`;
2. refuses non-PQ envelopes before any crypto
   (`writes.rs:715-727`);
3. verifies the signature (`writes.rs:728-730`);
4. applies chain-binding and nonce/balance/fee admission.

On success it returns the hex transaction hash. The SDK's hash is the node's
`Transaction::compute_tx_hash` (`transaction.rs:813-890`); parity asserts
equality.

### 3.6 Receipt

`stell_getTransactionReceipt` takes `{ "hash": "<hex>" }`
(`stellereum/src/rpc/reads.rs:1852-1943`). While the transaction is unknown or
still pooled, the answer is `{ "status": "pending" | "unknown" }`; a committed
transaction returns `tx_hash`, `height`, `block_hash`, `index`, `status`
(`success`/`failed`), `gas_limit`, `fee_charged`, `confirmations`, optional
contract/return/event fields.

`RpcClient::wait_for_receipt` polls until a committed receipt or the deadline.

### 3.7 Retry rule

`send_with_retry` (Rust) and `sendSigned` (JS) resend the **same** signed
bytes. They treat `rejected: transaction already in mempool` as success
(`stellereum/src/mempool.rs:465` renders `MempoolError::Duplicate` this way)
and retry only transport failures / explicit retryable RPC answers. A
signature, fee or nonce refusal is returned immediately.

---

## 4. Fee rule

The node's admission verdict is one comparison
(`Mempool::required_fee_for_tx`, `stellereum/src/mempool.rs:1051-1073`):

```text
required = effective_floor(from)
         + priority_fee_per_gas

effective_floor(from) = base_fee + failure_penalty(from)          (mempool.rs:844-847)
effective_floor_for_tx = effective_floor(from)
                       + 45_000  if tx is an explicit PQ1 activation (mempool.rs:1066-1072)
```

So the exact rule is:

```text
gas_limit >= base_fee + failure_penalty + (45_000 if explicit PQ1) + priority_fee_per_gas
```

- `base_fee` is a **static gas-unit floor**, not a dynamic fee market. The
  frozen minimum is 280,000 (`stellereum/src/mempool.rs:1394`,
  `stellereum/src/svm.rs:38`). `stell_baseFee` serves the current pool floor
  (`reads.rs:2355`).
- `PQ_ACTIVATION_SURCHARGE_GAS = 45_000`
  (`stellereum/src/mempool.rs:24`). It applies **only** to an explicit
  envelope carrying the raw public key, i.e. `is_pq_activation()` =
  explicit PQ1 with a pubkey (`transaction.rs:929`). Implicit envelopes do
  not pay it.
- `priority_fee_per_gas` is an explicit signed bid and must be covered by
  `gas_limit` (`mempool.rs:1051-1054`, `transaction.rs:547-552`).
- The balance check is separate and slightly stricter:
  `amount + gas_limit + (45_000 if explicit)` must be affordable
  (`Mempool::tx_cost`, `stellereum/src/mempool.rs:859-867`). The SDK's
  `Wallet::check_affordable` matches this.

The builder's default is the same formula with `failure_penalty = 0`:

```text
gas_limit = max(opcode_gas, base_fee) + (45_000 if explicit) + priority
```

Use `stell_estimateFee` with the signed transaction for the node's exact
answer including the sender's failure penalty. The raw-transaction arm is
`{ "tx": "<hex>" }` (`stellereum/src/rpc/reads.rs:327-342`); the response
fields are built at `reads.rs:505-525`.

Example (fresh account, explicit transfer, no bid):

```text
gas_limit = max(280_000, 280_000) + 45_000 = 325_000
balance needed = amount + 325_000 + 45_000
```

---

## 5. Chain-id binding

- The default chain id is **5757** (`stellereum/src/zkml.rs:191`).
  `stell_chainId` serves the node's configured id (`reads.rs:1072`).
  `eth_chainId` serves it as hex (`0x167d` for 5757,
  `stellereum/src/rpc/eth.rs:676`; `evm_adapter/types.rs:38`).
- Every SDK builder is **bound by default**. The envelope carries the chain id
  as 8 big-endian bytes (`envelope.rs:106-137`) and the signing preimage
  commits the same value under the `CHAIN_ID` tag
  (`transaction.rs:637-641`).
- The node checks the envelope's chain id against its own on admission and
  apply. A mismatch is refused with
  `Transaction chain_id mismatch: ...`
  (`stellereum/src/chain_binding.rs:161,166`; mempool/apply use the same
  string).
- Unbound envelopes are a legacy path. The compiled activation constant is
  `CHAIN_BINDING_NEVER = u64::MAX` today (`chain_binding.rs:41,48`), so the
  RPC admits unbound transactions but meters them; at a future activation
  height they are refused with
  `rejected: unbound transaction refused ... re-sign the transaction bound to
  chain_id <id>` (`chain_binding.rs:144-160`; wiring at
  `rpc/writes.rs:32-39,735-742`). **Bind in production.**
- A foreign-bound transaction is cryptographically valid on its own chain;
  the refusal is about replay domain, not signature
  (`chain_binding.rs:154-170`).

`TxBuilder::unbound()` exists only for tests; it prints a warning.

---

## 6. SF1 session grants

A grant is a master-signed Falcon authorization for a session key:

- struct and fields: `stellereum/src/zkml.rs:276-306`;
- bincode layout: the custom `Serialize` impl at `zkml.rs:308-365`
  (field order, schemes as one byte, both public keys as `Option<Vec<u8>>`);
- master signature preimage:
  `"STELL_SESSKEY_V1" || chain_id(8 BE) || master_address(32) ||
  session_pubkey(32) || valid_until(8 BE) || max_gas_spend(8 BE) ||
  scope(8 BE) || max_value_per_tx(8 BE)`
  (`zkml.rs:554-573`);
- verification: master signature + address derivation (`zkml.rs:669-700`),
  session signature (`zkml.rs:752-773`).

Transaction envelope (`sign_with_session_falcon512`,
`stellereum/src/sharding/transaction.rs:450-500`):

```text
session_signature(666) || "SF1" || bincode(SessionKeyAuthorization)
```

`tx.from` is the **master** address; the nonce/balance/fee are the master
account's. The session signs base + `SESSION` commitment (the grant is bound
into the message and the tx hash), not a `CHAIN_ID` commitment; the chain id
lives in the grant. Scopes are bit 0 transfer, bit 1 SVM payload, bit 2 actor
send (`zkml.rs:247-263`).

The SDK exposes `SessionGrant::new`, `.encode()`, `.decode()`,
`.verify_master()`, `.grants_scope()`, and
`TxBuilder::sign_with_session(&session_key, &grant)`.

---

## 7. Common errors

| Node answer (JSON-RPC `-32000` unless noted) | Meaning / fix |
| --- | --- |
| `Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope` (`writes.rs:715-727`) | The signature blob is not a PQ1/SF1 envelope. Sign with Falcon. |
| `invalid transaction signature` (`writes.rs:728-730`) | Wrong key/nonce/chain/fee preimage, modified bytes, or signature framing. Rebuild and sign; do not patch bytes. |
| `rejected: offered fee is below the base fee` (`mempool.rs:466`) | Raise `gas_limit` to at least `required_fee_for_tx`; use `stell_estimateFee`. |
| `rejected: sender cannot pay amount + gas_limit` (`mempool.rs:467`) | Fund the account for `amount + gas_limit + 45_000` (explicit). |
| `rejected: nonce gap: sender can execute X, got Y (fill the gap first)` (`mempool.rs:468-471`; `rpc/writes.rs:767`) | Send the missing nonce first; then re-sign with the right nonce. |
| `rejected: transaction already in mempool` (`mempool.rs:465`) | Success for submission: the exact transaction is already pooled. The SDK returns success (and the local hash). |
| `rejected: unbound transaction refused ...` (`chain_binding.rs:144-160`) | Bind to the node's chain id (`TxBuilder::chain_id`, default 5757). |
| `Transaction chain_id mismatch: chain id A does not match this chain (B)` (`chain_binding.rs:161-170`) | You signed for another chain. Re-sign bound to B. |
| `eth_sendRawTransaction` error with `data.reason = "full-pq-admission"` (`rpc/eth.rs:898-916`) | EVM/secp256k1 writes are refused. Use a PQ envelope via `stell_sendRawTransaction`. |
| HTTP 5xx / timeout | Transport failure. Retry the **same** signed bytes; the request may already have landed. |
| `-32602` / `bad hex` / `decode: ...` (`writes.rs:695-712`) | Malformed params or wire bytes; rebuild from the SDK instead of hand-encoding. |

The Rust `SdkError` maps the nonce-gap and insufficient-balance strings to
typed variants; JS maps JSON-RPC errors to `RpcError`/`ProviderRpcError` and
keeps `code`, `message`, `data`.

---

## 8. What is NOT supported (honest table)

| Not supported | Why / what to do instead |
| --- | --- |
| Native Falcon-512 signing in JavaScript | No WASM binding in-tree. Use the Rust CLI subprocess or localhost HTTP helper. |
| EVM contract execution | There is no EVM execution domain. `eth_sendRawTransaction` is refused (`rpc/eth.rs:1-30,898-916`); `eth_call`/`eth_getCode`/`eth_getProof` are reads over the node's mapping. |
| EVM account / `eth_sendTransaction` / `eth_sign` | The provider has no secp256k1 account; these throw 4200. |
| EVM ↔ PQ address binding | No on-chain binding exists; an EVM address is not a PQ identity. |
| `eth_subscribe` / WebSocket subscriptions | The node refuses `eth_subscribe`; `stell_subscribe` exists but the JS package does not implement its framing. |
| JSON-RPC batching | One request per call. |
| STS token operations, contract deploy, orderbook/PMM, bridge, governance, price feeds, zkML, actor mailbox, session publish/revoke, claim rewards, key rotation, delegate/unbond | Real opcodes, but outside this client's four wallet shapes. Use the node wallet/CLI or extend the SDK with a parity-tested encoder. |
| Paymaster / sponsored transactions | Revenue for another actor; the SDK mints first-party PQ1 or SF1 only. |
| Dynamic fee market / replacement-by-fee | `base_fee` is a static floor; `eth_gasPrice` is a testnet constant (`evm_adapter/adapter.rs:71`). Priority is an explicit signed bid. |
| Automatic nonce-gap filling / mempool replacement | The SDK reads the nonce and returns the node's gap error; it will not invent transactions. |
| SPV proof verification | Read helpers expose the node's answers; no light-client verifier is included. |
| Encrypted keystore / hardware wallet / multisig | Key files are plaintext JSON at mode 0600; no HSMS/MPC. |
| Importing a node operator `FalconKeypair::to_bytes` key | The node stores expanded `(f,g,F,G,h)` polynomials (`post_quantum.rs:1741`); the SDK stores PQClean `(f,g,F)+public`. Public keys and signatures interoperate; the private container does not. Generate an SDK key for wallet use. A validator that must sign `unjail` with its existing node key needs the node's own CLI. |
| ML-DSA-44 | Disabled and refused by the node (`post_quantum.rs:188-206`). |
| Contract ABI manifest fetching/decoding | The builder takes typed `CallArg`s; use `stell_getContractAbi` yourself if you need the manifest. |

---

## 9. Verification

```bash
# Rust (thin client; no node crate)
cd stellereum-sdk
cargo test
cargo clippy --all-targets -- -D warnings

# Rust parity with the node's own decoder/verifier (optional, heavy)
cargo test --features node-parity

# TypeScript
cd ../sdk-js
npm install
npm test
npm run typecheck
npm run build
```

The parity suite covers:

- `verify_pq_signature` accepts the SDK signature;
- `derive_pq_address` equals the SDK address;
- `bincode(Transaction)` decodes into the node's `Transaction` and
  `verify_signature()` passes;
- explicit, implicit, unbound and priority-bid envelopes;
- stake / unjail / contract-call payloads equal the node's `bincode(OpCode)`;
- calldata equals `ContractAbi::encode_args`;
- SF1 grant bytes decode into `SessionKeyAuthorization` and both its verifier
  and the transaction verifier pass;
- transaction hashes equal `compute_tx_hash`;
- retry tests capture every HTTP body and assert identical bytes/nonce.

---

## 10. Node source map (claims used above)

| Claim | Node location |
| --- | --- |
| Live PQ schemes / Falcon-512 only | `stellereum/src/post_quantum.rs:154,188-206` |
| Address domain and derivation | `stellereum/src/post_quantum.rs:111,117,262` |
| Canonical signature header `0x29`, 666 bytes | `stellereum/src/post_quantum.rs:2162-2181,2213` |
| PQ1 envelope encode/decode | `stellereum/src/sharding/envelope.rs:17,106,187` |
| `SF1` tag / session framing | `stellereum/src/sharding/envelope.rs:395`; `transaction.rs:450` |
| Transaction constructors | `stellereum/src/sharding/transaction.rs:950,983,1012,1050` |
| Signing preimage / payload / chain commitment | `stellereum/src/sharding/transaction.rs:521,553,637,1319,1357` |
| Signature verification + address pin | `stellereum/src/sharding/transaction.rs:1138-1310,1379` |
| Transaction hash preimage | `stellereum/src/sharding/transaction.rs:813-890` |
| `is_pq_activation` (surcharge trigger) | `stellereum/src/sharding/transaction.rs:929` |
| Fee floor / surcharge / priority | `stellereum/src/mempool.rs:24,844,859,1051,1066,1394` |
| Nonce-gap message | `stellereum/src/mempool.rs:465-471` |
| Chain-binding activation and refusal strings | `stellereum/src/chain_binding.rs:41,48,144,161,166,199,220` |
| `stell_sendRawTransaction` admission | `stellereum/src/rpc/writes.rs:695-751` |
| `stell_estimateFee` raw-tx arm / answer | `stellereum/src/rpc/reads.rs:327-342,505-525` |
| `stell_getBalance` | `stellereum/src/rpc/reads.rs:1404` |
| `stell_getBlock` | `stellereum/src/rpc/reads.rs:1197` |
| `stell_getTransactionReceipt` | `stellereum/src/rpc/reads.rs:1852` |
| `stell_getValidators` | `stellereum/src/rpc/reads.rs:2168` |
| `stell_baseFee` | `stellereum/src/rpc/reads.rs:2355` |
| `eth_*` surface / EVM write refusal | `stellereum/src/rpc/eth.rs:1-30,676,771,865,898-916` |
| SVM opcodes and gas table | `stellereum/src/svm.rs:38,83,92,94,467,548,994,1124` |
| Session grant struct / signature / scopes | `stellereum/src/zkml.rs:180,247-263,276,554,584,669,752` |
| Stl57 address format | `stellereum/src/address.rs:57` |
| Chain id default 5757 | `stellereum/src/zkml.rs:191` |
| `eth_chainId` hex formatting | `stellereum/src/evm_adapter/types.rs:38` |
