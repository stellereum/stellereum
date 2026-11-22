---
title: Wallet signing
description: The Stellereum message-signing standard — STELL-MSGSIG-V1 and STELL-TYPEDDATA-V1.
outline: deep
---

# Wallet message signing

This is the standard a wallet, dApp, hardware signer or multisig tool
implements when it signs **something that is not a transaction**.

It is deliberately narrow. It standardises:

- the message preimage;
- message signing and verification for Ed25519, Falcon-512 and Hybrid;
- the structured (typed-data) encoding for contract calls;
- the signature envelope.

It does **not** change the transaction format or the address format.

::: danger The one-line guarantee
A wallet message signature can **never** be replayed as a transaction
signature, and a raw transaction signature is never accepted as a message
signature. The two have different preimages, different domain tags and
different envelopes.
:::

## Why a standard exists

Before this standard the wallet signed with a proprietary SHA-256 seed
derivation that was incompatible with anything but its own CLI. There was no
documented way for a dApp, a hardware wallet or a multisig tool to ask a
Stellereum account to authorize a message or a readable contract call.

The reference models are EIP-191 / EIP-712 (Ethereum `personal_sign` and typed
data), NEP-413 (NEAR message signing) and TON's signed-payload conventions.

Implementation: `stellereum/src/wallet_signing.rs`. RPC:
`stell_signMessage`, `stell_verifyMessage`, `stell_signTypedData`,
`stell_verifyTypedData`. CLI: `stellereum wallet sign | verify |
sign-typed-data | verify-typed-data`.

## Plain message preimage (`STELL-MSGSIG-V1`)

All integers are unsigned big-endian. `‖` is concatenation.

```text
STELL_MESSAGE_PREFIX (27 B):  "Stellereum Signed Message:\n"
                             (0x5374…0a, trailing LF included)
‖ DOMAIN_TAG        (15 B):  "STELL-MSGSIG-V1"
‖ chain_id          (u64 BE, 8 B)
‖ message_len       (u64 BE, 8 B — length of the bytes that follow)
‖ message bytes     (message_len B)
```

Worked example — message `"hello stellereum"` on chain id `5757`
(`0x167d`):

```text
5374656c6c657265756d205369676e6564204d6573736167653a0a
5354454c4c2d4d53475349472d5631
000000000000167d
0000000000000010
68656c6c6f207374656c6c657265756d
```

Each field does a job:

- **chain id** binds the signature to one deployment. The verifier rebuilds
  the preimage with *its* chain id, never one taken from the envelope (the
  envelope carries none), so a testnet signature verifies as invalid on
  mainnet.
- **length prefix** makes the framing unambiguous: `prefix ‖ a ‖ b` cannot
  collide with `prefix ‖ ab`.
- **human-readable prefix** keeps a wallet signature visually and
  cryptographically distinct from a transaction signature and from another
  chain's `personal_sign`.

## Typed data (`STELL-TYPEDDATA-V1`)

A structured contract call the wallet **displays** and the user authorizes:

```json
{
  "args": { "amount": 100, "to": "alice" },
  "chain_id": "5757",
  "contract": "0xabab…ab",
  "method": "transfer",
  "nonce": "7",
  "value": "1000"
}
```

Rules:

- keys are sorted: `args`, `chain_id`, `contract`, `method`, `nonce`,
  `value`;
- `contract` is a 32-byte address, lowercase `0x`-prefixed hex;
- `method` is non-empty and at most 256 bytes;
- `args` is any JSON value; objects are key-sorted **recursively** and emitted
  with no whitespace;
- `value`, `nonce` and `chain_id` are **decimal strings**, because a `u64`
  does not survive a JavaScript `Number`.

Preimage:

```text
STELL_MESSAGE_PREFIX (27 B)
‖ "STELL-TYPEDDATA-V1" (18 B)
‖ chain_id          (u64 BE, 8 B — the same chain id as inside the JSON)
‖ canonical_len     (u64 BE, 8 B)
‖ canonical JSON bytes
```

Two objects with the same content in different key order produce
byte-identical canonical JSON and therefore byte-identical signatures.

Canonical form of the example above (one line, no spaces):

```json
{"args":{"amount":100,"to":"alice"},"chain_id":"5757","contract":"0xabab…ab","method":"transfer","nonce":"7","value":"1000"}
```

Limits are fail-closed: canonical JSON at most **64 KiB**, plain messages at
most **64 KiB**. Larger payloads must be hashed by the caller, and the digest
signed as typed data.

## Domain separation: why a message signature is not a transaction

This is the part integrators ask about, so it is worth being explicit.

| | Transaction signature | Message signature |
| --- | --- | --- |
| Envelope start | `"PQ1"` (or `"SF1"`) | `0x01` version byte |
| Preimage start | `from ‖ to ‖ amount ‖ gas_limit ‖ nonce ‖ shards …` | `"Stellereum Signed Message:\n"` |
| Domain tag | `PAYLOAD`, `PRIORITY`, `CHAIN_ID` | `STELL-MSGSIG-V1` or `STELL-TYPEDDATA-V1` |
| Verification site | consensus admission / apply | `stell_verifyMessage` / `stell_verifyTypedData` |
| What it authorizes | state transition | an off-chain statement |
| Replayable as the other? | **No** | **No** |

There are four independent barriers:

1. **Different bytes.** The transaction verifier reconstructs
   `base_signing_message` and checks the envelope signature against it. The
   message verifier reconstructs the prefixed preimage. A signature over one
   does not verify over the other.
2. **Different envelope.** `stell_sendRawTransaction` accepts a bincode
   `Transaction` whose `signature` field must be `PQ1`/`SF1`. A wallet
   signature envelope (`01 01 0020 …`) is not a `PQ1` envelope; admission
   refuses it before any crypto.
3. **Different domain tag.** Even if an attacker engineered byte-identical
   message content, `STELL-MSGSIG-V1`, `STELL-TYPEDDATA-V1`, `PAYLOAD` and
   `CHAIN_ID` are distinct tags. Message and typed-data signatures are also
   not interchangeable with each other.
4. **Chain binding.** A signature minted for chain `5757` does not verify for
   `5758` or `1`, for messages and typed data, for all three schemes.

Pinned by tests: `typed_data_domain_differs_from_message_domain`,
`chain_binding_*`, tamper tests and the RPC-level matrix.

::: tip Practical consequence
A dApp can safely ask a user to sign a login nonce, an order intent or a
readable contract call. That signature cannot move funds, cannot be
rebroadcast as a transaction and cannot be replayed on another chain.
:::

## Schemes, keys, addresses

| scheme id | scheme | public key | signature | address |
| --- | --- | --- | --- | --- |
| `0x01` | Ed25519 | 32 B | 64 B | the public key itself |
| `0x02` | Falcon-512 | 897 B | 666 B | `BLAKE3("STL_ADDR_V4" ‖ 0x02 ‖ pubkey ‖ zero_salt)` |
| `0x04` | Hybrid (Ed25519 + Falcon-512) | 929 B | 730 B | `BLAKE3("STL_ADDR_V4" ‖ 0x04 ‖ pubkey ‖ zero_salt)` |

- `0x03` (ML-DSA-44) is **disabled fail-closed** everywhere. The decoder
  refuses it loudly and verification returns `false`.
- The salt for wallet-signing address derivation is always the zero salt, so
  an address is a pure function of `(scheme, pubkey)` and any verifier can
  re-derive it.
- Hybrid signs the preimage with **both** keys and concatenates Ed25519 first,
  Falcon second. A hybrid signature verifies only when both halves verify.
- Falcon-512 signatures are **randomized** (FIPS 206 sampler): two signatures
  over the same message differ and both verify. Only Ed25519 vectors are
  pinned byte-for-byte.

## Signature envelope

```text
version    (1 B)   = 0x01
scheme     (1 B)   = 0x01 | 0x02 | 0x04
pubkey_len (u16 BE, 2 B) = scheme.pubkey_size() EXACTLY
pubkey     (pubkey_len B)
sig_len    (u16 BE, 2 B) = scheme.signature_size() EXACTLY
signature  (sig_len B)
```

Sizes on the wire: Ed25519 **102 B**, Falcon-512 **1569 B**, Hybrid
**1665 B**.

The public key rides in the envelope because a 32-byte Falcon/Hybrid address
is a hash and cannot verify on its own. The verifier re-derives the address
from `(scheme, pubkey)` and compares it to the claimed address **before**
checking the signature, so a signature under key K can never be presented as a
signature by address A ≠ addr(K).

Decoding is strict and fail-closed, in this order: minimum length → version is
`0x01` → scheme is live → `pubkey_len` is canonical → Ed25519 key is a valid
curve point → `sig_len` is canonical → **no trailing bytes**.

## Test vectors

Seed `0x42…42` (32 bytes), chain id `5757`, message `"hello stellereum"`:

```text
address (Ed25519): 2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12

preimage:
5374656c6c657265756d205369676e6564204d6573736167653a0a
5354454c4c2d4d53475349472d5631
000000000000167d
0000000000000010
68656c6c6f207374656c6c657265756d

signature:
010100202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12
0040a8ebb8d6b79fcd9c5937fa53789ba4b138c56e7ce1d8356817a1d4ae03c0fc4e5d24e6
30b106ce5591cd948b1e059d29caf495181c9deeb081685938c83d8e0d
```

Envelope anatomy: `01` version, `01` Ed25519, `0020` 32-byte public key,
`2152…db12`, `0040` 64-byte signature, `a8eb…8e0d`.

Deterministic addresses (Falcon seed `0x77…77`; Hybrid Ed `0x42…42` +
Falcon `0x77…77`; zero salt):

```text
Falcon-512 address: 549f119ff1a76b7ce82cc87bc86b130db8136f189068209dcbf9b00ef7125cd5
Hybrid address:     84cb0826fa62b1953b06befa2bfe602b4ea10f2d76672242796147ae7d94fbed
```

Falcon and Hybrid signatures are randomized and intentionally not pinned.

## Library API

```rust
message_preimage(chain_id, message) -> Vec<u8>
canonical_typed_data_json(&TypedCallData) -> String
typed_data_preimage(&TypedCallData) -> Result<Vec<u8>, String>

WalletSigningKey::{ed25519(seed), falcon_from_seed(&seed), hybrid(ed, falcon)}
  .address() -> [u8; 32]
  .sign_message(chain_id, message) -> Result<WalletSignature, String>
  .sign_typed_data(&data) -> Result<(WalletSignature, String /* canonical */), String>

verify_message(&address, chain_id, message, &WalletSignature) -> bool
verify_typed_data(&address, &TypedCallData, &WalletSignature) -> bool
```

Verification is total: it returns `bool`, never a panic. A wrong chain, a
tampered message, a wrong address, a malformed envelope and a disabled scheme
all return `false`.

## RPC binding

| Method | Auth | What it does |
| --- | --- | --- |
| `stell_signMessage` | token, loopback + dev key | signs with the **node's** key — testing/devnet only |
| `stell_verifyMessage` | public | verifies Ed25519, Falcon-512, Hybrid |
| `stell_signTypedData` | token, loopback + dev key | signs typed data with the node's key — testing/devnet only |
| `stell_verifyTypedData` | public | re-encodes canonical JSON locally and verifies |

::: danger Production wallets sign locally
`stell_signMessage` and `stell_signTypedData` exist so a devnet can be driven
without a wallet. They sign with the node's identity/validator key and are
fail-closed without `STELL_RPC_AUTH_TOKEN`, a loopback peer and an explicitly
configured dev signing key. **Never ship keys to a node.** Use
`stellereum wallet sign` or the library.
:::

### `stell_signMessage`

Parameters: `{"message": "<utf8>"}` XOR `{"message_hex": "<hex>"}`, plus
optional `{"chain_id": <u64>}` and `{"token": "<api token>"}`.

```json
{"jsonrpc":"2.0","id":1,"method":"stell_signMessage",
 "params":{"message":"hello stellereum","token":"<api token>"}}
```

```json
{"jsonrpc":"2.0","id":1,"result":{
  "address":"2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
  "scheme":"Ed25519","scheme_id":1,
  "signature":"01010020…",
  "preimage":"5374656c…",
  "chain_id":5757
}}
```

### `stell_verifyMessage`

Parameters: `{"address","message"|"message_hex","signature","chain_id"?}`.

```json
{"jsonrpc":"2.0","id":1,"result":{
  "valid":true,"address":"<hex>","scheme":"Ed25519",
  "scheme_id":1,"chain_id":5757
}}
```

A **malformed** envelope is `-32602 "bad signature envelope: …"`, not
`valid:false`. A well-formed but wrong signature is `valid:false`.

### `stell_signTypedData` / `stell_verifyTypedData`

The sign arm takes the structured fields `{contract, method, args?, value?,
nonce?, chain_id?, token?}` and answers with the exact canonical JSON it
signed:

```json
{"jsonrpc":"2.0","id":1,"result":{
  "address":"<hex>","scheme":"Ed25519","scheme_id":1,
  "signature":"<hex envelope>",
  "canonical":"{\"args\":{\"amount\":100,\"to\":\"alice\"},\"chain_id\":\"5757\",…}",
  "chain_id":5757
}}
```

Display `canonical` to the user. It is the exact bytes the signature commits
to. Key order in `args` does not matter.

## CLI

```bash
# Sign locally — the key never leaves this machine.
stellereum wallet sign --from-key <hex seed> --message "hello" [--chain-id 5757]
stellereum wallet sign --scheme falcon --falcon-seed <hex seed> --message "hello"
stellereum wallet sign --scheme hybrid \
  --from-key <hex> --falcon-key-file ./keys/falcon.key --message "hello"

# Verify offline — no key, no network; exit non-zero when invalid.
stellereum wallet verify --address <hex> --message "hello" \
  --signature <hex envelope>

stellereum wallet sign-typed-data --from-key <hex> \
  --contract <hex> --method transfer \
  --args '{"to":"alice","amount":100}' --value 1000 --nonce 7

stellereum wallet verify-typed-data --address <hex> \
  --contract <hex> --method transfer \
  --args '{"amount":100,"to":"alice"}' --value 1000 --nonce 7 \
  --signature <hex envelope>
```

`verify-typed-data` accepts `--args` in any key order; it re-encodes
canonically before verifying.

## Guarantees

Each is pinned by a test:

- cross-scheme round trips for Ed25519, Falcon-512 and Hybrid; a signature
  presented under another address fails;
- chain binding for messages and typed data, all three schemes, RPC included;
- any message-byte change fails;
- different key orders produce identical canonical JSON and identical
  Ed25519 signatures;
- strict envelope decoding refuses wrong version, `0x03`, unknown schemes,
  wrong lengths, truncation and trailing bytes;
- the RPC sign arms require the token and a configured node key; verify arms
  are public; malformed envelopes are `-32602`.

## What this does not do

- It does not authorize a state transition. Use a transaction.
- It does not create a reusable session key. Use
  [session keys](/sdk/session-keys).
- It does not prove ownership of an EVM secp256k1 address. Use
  [EVM binding](/sdk/rust#evm-binding-and-carrier).
- It does not provide encryption, replay windows or nonce tracking for off-chain
  protocols. Those belong to the application; include a nonce and an expiry in
  the message or `args` yourself.

## Next

Read [Session keys](/sdk/session-keys) for delegated transaction authority, or [Rust SDK](/sdk/rust#evm-binding-and-carrier) for EVM binding and carrier flows.
