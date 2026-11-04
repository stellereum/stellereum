# Stellereum Wallet Signature Standard

**Status: IMPLEMENTED** (audit P2 item 15, *"стандарт подписи кошелька"*: closed).
Implementation: `src/wallet_signing.rs`. RPC: `stell_signMessage`,
`stell_verifyMessage`, `stell_signTypedData`, `stell_verifyTypedData`
(`src/rpc.rs`). CLI: `stellereum wallet sign | verify | sign-typed-data |
verify-typed-data` (`src/main.rs`).

## 1. Why this standard exists

The wallet used to sign with a proprietary SHA-256 seed derivation that was
"incompatible with anything but its own CLI", and there was no documented
standard for how a wallet signs anything that is not a transaction. Dapps,
hardware wallets and multisig tooling had nothing to implement against.

This document IS that standard. Reference models: EIP-191/EIP-712 (Ethereum
`personal_sign` / typed data), NEP-413 (NEAR message signing), TON's signed
payload conventions.

Scope (deliberately narrow):

* **Standardized here:** the MESSAGE preimage, message signing/verification for
  Ed25519, Falcon-512 and Hybrid, the structured (typed-data) encoding for
  contract calls, and the signature envelope.
* **NOT changed:** the transaction format and the address format. This is
  purely the message-signing layer. A wallet signature can never be replayed
  as a transaction signature (different preimage, different domain tag) and a
  raw transaction signature is never accepted as a message signature.

## 2. Preimage layout (byte-for-byte)

All integers are unsigned big-endian. `||` is concatenation.

### 2.1 Plain message

```text
STELL_MESSAGE_PREFIX (27 B):  "Stellereum Signed Message:\n" (0x5374…0a, trailing LF included)
|| DOMAIN_TAG       (15 B):  "STELL-MSGSIG-V1"
|| chain_id         (u64 BE, 8 B)
|| message_len      (u64 BE, 8 B — length of the message bytes that follow)
|| message bytes    (message_len B)
```

Example — message `"hello stellereum"` on chain id 5757 (`0x167d`):

```text
preimage = 5374656c6c657265756d205369676e6564204d6573736167653a0a
           5354454c4c2d4d53475349472d5631
           000000000000167d
           0000000000000010
           68656c6c6f207374656c6c657265756d
```

The chain id binds the signature to one deployment: the verifier rebuilds the
preimage with ITS chain id (never one taken from the envelope — the envelope
carries none), so a testnet signature verifies as INVALID on mainnet. The
length prefix makes the framing unambiguous (no `prefix || a || b` vs
`prefix || ab` collisions). The human-readable prefix keeps a wallet signature
visually and cryptographically distinct from a transaction signature and from
any other chain's `personal_sign`.

### 2.2 Structured (typed-data) message

The same framing, but under the typed-data domain tag, over the CANONICAL JSON
bytes of §3:

```text
STELL_MESSAGE_PREFIX (27 B)
|| "STELL-TYPEDDATA-V1" (18 B)
|| chain_id         (u64 BE, 8 B — the SAME chain_id as inside the JSON)
|| canonical_len    (u64 BE, 8 B)
|| canonical JSON bytes
```

The domain tags separate the two worlds: a message signature is never valid
as a typed-data signature and back, even over identical bytes (pinned by
test `typed_data_domain_differs_from_message_domain`).

## 3. Typed data: canonical JSON (EIP-712-style readable signing)

A structured contract call the wallet DISPLAYS and the user authorizes:

```json
{"args":…,"chain_id":"…","contract":"0x…","method":"…","nonce":"…","value":"…"}
```

* Fixed key order (sorted — see below): `args`, `chain_id`, `contract`,
  `method`, `nonce`, `value`.
* `contract`: 32-byte address, `0x`-prefixed lowercase hex.
* `method`: non-empty, at most 256 bytes.
* `args`: any JSON value; objects are key-sorted RECURSIVELY, no whitespace.
* `value`, `nonce`, `chain_id`: DECIMAL STRINGS (the RPC convention — `u64`
  does not survive a JavaScript `Number`), so every type is explicit.

Example — contract `0xabab…ab` (32 bytes), method `transfer`,
args `{"to":"alice","amount":100}` (any key order), value 1000, nonce 7,
chain 5757:

```json
{"args":{"amount":100,"to":"alice"},"chain_id":"5757","contract":"0xabab…ab","method":"transfer","nonce":"7","value":"1000"}
```

Two JSON objects with the same content in different key order produce
byte-identical canonical JSON and therefore byte-identical signatures
(pinned by tests, library and RPC level).

Limits (fail-closed): canonical JSON at most 64 KiB; plain messages at most
64 KiB. Larger payloads must be hashed by the caller and the digest signed
as typed data instead.

## 4. Schemes, keys, addresses

| scheme id | scheme | public key | signature | address |
| --- | --- | --- | --- | --- |
| `0x01` | Ed25519 | 32 B | 64 B | the public key itself |
| `0x02` | Falcon-512 | 897 B | 666 B | `blake3("STL_ADDR_V4" \|\| 0x02 \|\| pubkey \|\| zero_salt)` |
| `0x04` | Hybrid (Ed25519 + Falcon-512) | 929 B (32 + 897) | 730 B (64 + 666) | `blake3("STL_ADDR_V4" \|\| 0x04 \|\| pubkey \|\| zero_salt)` |

* `0x03` (ML-DSA-44) is DISABLED fail-closed everywhere: the decoder refuses
  it loudly and verification returns `false`. It is kept in the enum only so
  every `match` stays exhaustive.
* The salt for wallet-signing address derivation is always the zero salt
  (`[0u8; 16]`), so an address is a pure function of `(scheme, pubkey)` and
  any verifier can re-derive it without extra parameters.
* Hybrid signs the preimage with BOTH keys and concatenates (Ed first,
  Falcon second) — the same rule `verify_pq_signature` checks, so a hybrid
  signature verifies only when BOTH halves verify.
* Falcon-512 signatures are RANDOMIZED (FIPS 206 sampler): two signatures over
  the same message differ and both verify. Only Ed25519 vectors are pinned
  byte-for-byte below.

## 5. Envelope format

Wire layout, byte-for-byte:

```text
version    (1 B)   = 0x01
scheme     (1 B)   = 0x01 | 0x02 | 0x04
pubkey_len (u16 BE, 2 B) = scheme.pubkey_size() EXACTLY
pubkey     (pubkey_len B)
sig_len    (u16 BE, 2 B) = scheme.signature_size() EXACTLY
signature  (sig_len B)
```

The public key rides in the envelope because a 32-byte Falcon-512/Hybrid
address is a HASH — it cannot verify on its own. The verifier re-derives the
address from `(scheme, pubkey)` and compares it to the claimed address BEFORE
checking the signature, so a signature under key K can never be presented as
a signature by address A ≠ addr(K).

Sizes on the wire: Ed25519 **102 B**, Falcon-512 **1569 B**, Hybrid **1665 B**.

Decoding is strict fail-closed, in this order: minimum length → version is
`0x01` → scheme is live (`from_id` refuses `0x03` and unknown ids loudly) →
`pubkey_len` equals the scheme's canonical size → Ed25519 pubkey is a valid
curve point → `sig_len` equals the scheme's canonical size → NO trailing
bytes. Any deviation is an error, never a guess.

## 6. API (`src/wallet_signing.rs`)

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

Verification is TOTAL (returns `bool`, never errors): wrong chain, tampered
message, wrong address, malformed envelope, disabled scheme — all `false`.

## 7. RPC

| method | auth | signs/verifies | notes |
| --- | --- | --- | --- |
| `stell_signMessage` | **yes** (`STELL_RPC_AUTH_TOKEN`) | signs, node Ed25519 key | testing/devnet ONLY |
| `stell_verifyMessage` | — (public) | verifies all 3 schemes | no secret, no side effects |
| `stell_signTypedData` | **yes** | signs, node Ed25519 key | testing/devnet ONLY |
| `stell_verifyTypedData` | — (public) | verifies all 3 schemes | canonical JSON re-encoded locally |

`stell_signMessage` params: `{"message": "…"} XOR {"message_hex": "0x…"},
["chain_id"], ["token"]}` → `{"address","scheme","scheme_id","signature",
"preimage","chain_id"}`. The node signs with ITS OWN key (wired to the
validator/identity key at startup); when no signing key is configured the arm
refuses fail-closed with `-32000`. The auth gate follows the node's standard
rule (required when `STELL_RPC_AUTH_TOKEN` is set, open local/dev mode when
it is not) — production MUST set the token, and production wallets MUST sign
locally and never ship keys to a node.

`stell_verifyMessage` params: `{"address","message"|"message_hex",
"signature","chain_id"?}` → `{"valid","address","scheme","scheme_id",
"chain_id"}`. A malformed envelope is `-32602`, never "invalid".

`stell_signTypedData` / `stell_verifyTypedData` take the STRUCTURED fields
`{"contract","method","args"?,"value"?,"nonce"?,"chain_id"?,"token"?}` plus
`{"address","signature"}` for verify. The sign arm answers with the `canonical`
JSON it signed — display THAT to the user.

## 8. CLI (`stellereum wallet …`)

```sh
# Sign locally (the key never leaves this machine):
stellereum wallet sign --from-key <hex seed> --message "hello" [--chain-id 5757]
stellereum wallet sign --scheme falcon --falcon-seed <hex seed> --message "hello"
stellereum wallet sign --scheme hybrid --from-key <hex> --falcon-key-file ./keys/falcon.key --message "hello"

# Verify offline (no key, no network; exit non-zero when INVALID):
stellereum wallet verify --address <hex> --message "hello" --signature <hex envelope>
stellereum wallet sign-typed-data --from-key <hex> --contract <hex> --method transfer \
    --args '{"to":"alice","amount":100}' --value 1000 --nonce 7
stellereum wallet verify-typed-data --address <hex> --contract <hex> --method transfer \
    --args '{"amount":100,"to":"alice"}' --value 1000 --nonce 7 --signature <hex envelope>
```

`verify-typed-data` accepts the args in ANY key order — it re-encodes
canonically before checking.

## 9. Test vectors

Seed `0x42…42` (32 bytes), chain id 5757, message `"hello stellereum"`:

```text
address (Ed25519): 2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12
preimage:          5374656c6c657265756d205369676e6564204d6573736167653a0a5354454c4c2d4d53475349472d5631
                   000000000000167d000000000000001068656c6c6f207374656c6c657265756d
signature:         010100202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db120040
                   a8ebb8d6b79fcd9c5937fa53789ba4b138c56e7ce1d8356817a1d4ae03c0fc4e5d24e630b106ce
                   5591cd948b1e059d29caf495181c9deeb081685938c83d8e0d
```

Envelope anatomy of that signature: `01` (version) `01` (Ed25519) `0020`
(32-byte pubkey) `2152…881db12` `0040` (64-byte sig) `a8eb…8e0d`.

Deterministic addresses (seed `0x77…77` for Falcon, Ed `0x42…42` + Falcon
`0x77…77` for Hybrid, zero salt):

```text
Falcon-512 address: 549f119ff1a76b7ce82cc87bc86b130db8136f189068209dcbf9b00ef7125cd5
Hybrid address:     84cb0826fa62b1953b06befa2bfe602b4ea10f2d76672242796147ae7d94fbed
```

(Falcon/Hybrid SIGNATURES are randomized and intentionally not pinned —
only the addresses and the preimage are.)

## 10. Guarantees (each pinned by a test)

* Cross-scheme round trips: every scheme signs and verifies
  (`cross_scheme_matrix`, `ed25519_round_trip`, `falcon512_round_trip`,
  `hybrid_round_trip`); a signature presented under another address fails.
* Chain binding: a signature minted for 5757 does NOT verify for 5758 or 1,
  for messages AND typed data, for all three schemes — RPC level included.
* Tampering: any message byte change fails, for all schemes, library and RPC.
* Canonical typed data: different key orders → identical JSON, identical
  Ed25519 signature; what the user saw is what verifies.
* Strict decoding: wrong version, `0x03`, unknown scheme, wrong lengths,
  truncated envelope, trailing byte — all refused.
* RPC: sign needs the token on a gated node, verify is public; sign without
  a configured node key fails closed; malformed envelopes are `-32602`.
