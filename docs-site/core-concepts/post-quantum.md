# Post-quantum

Stellereum's threat model assumes a quantum adversary can forge classical signatures. The network therefore uses post-quantum cryptography for **consensus votes and value-moving transactions**, not as an optional add-on.

## The two primitives

| Purpose | Primitive | Sizes |
| --- | --- | --- |
| Signatures | **Falcon-512** (FIPS 206 / FN-DSA family, NIST Level 1) | 897-byte public key, 666-byte signature |
| Transport key exchange | **ML-KEM-768** | ML-KEM encapsulation key in the node's `e2e.key` |
| Transport authentication | Falcon-512 P2P identity | Separate from the consensus key |

Falcon-512 is the only accepted transaction and vote signature scheme. ML-KEM-768 protects node-to-node transport. The node also holds a Falcon-512 P2P identity so transport peers are authenticated with the same post-quantum family.

## There is no classical signature lane

A common shortcut is to keep Ed25519 or secp256k1 as a fallback. Stellereum does not:

- Ed25519 is **not** accepted as the authority for a transaction signature, a validator vote, or a faucet signature.
- secp256k1 is **not** a consensus credential. The read-only EVM adapter can route a PQ-signed carrier, but the secp256k1 signature inside the EVM bytes is advisory and never sufficient.
- A pure-PQ node refuses a classical transaction with `invalid transaction signature` instead of downgrading it.

Ed25519 survives in exactly one place **within consensus and value transfer**: the 32-byte **validator id / voter id**. The consensus vote frame still carries a 64-byte Ed25519 half for wire compatibility, but the current pure-PQ verifier checks only the Falcon-512 half against the voter's registered key at that height; the Ed25519 bytes are not an authority. The separate wallet message-signing standard also supports Ed25519 for off-chain statements, with a preimage and envelope that cannot be replayed as a transaction (see [Wallets & signing](/sdk/wallets-and-signing)).

::: info ML-DSA-44 is a placeholder, not a live lane
The scheme enum still contains ML-DSA-44 (`0x03`) so exhaustive matches keep compiling, but admission refuses it because there is no FIPS-204 verifier in the codebase. Only Falcon-512 (`0x02`) is accepted. Do not build against an ML-DSA-44 path.
:::

## The PQ1 envelope

Every Falcon transaction signature travels in a `PQ1` envelope. The canonical encoding is:

```text
"PQ1"            3 bytes   magic
scheme_id        1 byte    0x02 = Falcon-512
is_implicit      1 byte    0 = public key attached, 1 = rely on registry
pubkey_len       2 bytes   little-endian; 0 when implicit
pubkey           N bytes   897 for Falcon-512 (explicit only)
salt             16 bytes  omitted when implicit; default 16 zero bytes
sig_len          2 bytes   little-endian; 666 for Falcon-512
signature        N bytes
chain_id         8 bytes   optional trailing big-endian chain binding
```

The decoder is strict: lengths are pinned to the scheme, the implicit flag must be `0` or `1`, an implicit envelope must carry no public key, and an explicit envelope must carry exactly the scheme's public-key size. This removes signature malleability from byte-level re-encodings and makes a transaction hash stable.

### Explicit first spend, implicit later

A fresh account does not exist in the state trie. Its first transaction carries the full 897-byte Falcon public key so the node can derive and check the address. After that, the key is registered in the in-memory implicit key registry and later transactions can omit it, saving roughly 900 bytes per transaction. The registry is a bandwidth optimization, not a trust anchor: a node that does not have the key can demand the explicit form or reject the transaction, but it cannot accept a signature that does not verify.

### Chain binding

When a chain id is present, it is appended to the envelope and also included in the signed message. The transaction is then valid only on that chain. `wallet send-pq --chain-id 5757` and the faucet's chain-bound path both produce this form. A signature made for another chain, or a replayed envelope with a different id, fails verification.

## Address derivation

The address commits to the scheme, the public key and a salt:

```text
address = BLAKE3("STL_ADDR_V4" ‖ scheme_id ‖ falcon_public_key ‖ salt)
```

The default salt is 16 zero bytes; `scheme_id` is `0x02`. Because the key is in the preimage, one key maps to exactly one address, and a new key is a new address. See [Addresses](/get-started/addresses) for the display and routing forms.

## Validator key hierarchy

A validator is not a single key. Ruleset v7 separates three roles:

| Role | Type | What it does |
| --- | --- | --- |
| **Validator id / voter id** | 32-byte Ed25519-shaped identifier | Stable name in the validator set and the recipient of stake accounting |
| **Hot voting key** | Falcon-512 | Signs prevotes, precommits and other consensus messages |
| **Cold withdrawal key** | Falcon-512 | Controls stake, unbonding, withdrawal and commission changes |

Registration is `stellereum validator register-validator` (OpCode 59). It submits a Falcon proof of possession for **both** the cold withdrawal key and the hot voting key, in addition to the stake amount. The proofs bind the keys to the validator id under the `STELL_PQ_KEY_POP_V1` and `STELL_VAL_ID_V1` domains.

Key lifecycle operations are native opcodes:

| OpCode | Operation |
| --- | --- |
| 59 | Register validator (cold + hot PoP) |
| 60 | Announce or cancel a voting-key rotation |
| 61 | Change the cold withdrawal address with new-key PoP |
| 62 | One-time claim of a withdrawal address for a pre-v7 validator |
| 63 | Announce a commission change |
| 64 | Apply a matured commission change |

Rotation is announced ahead of time, sequenced with `next_seq` to stop replay, and becomes effective at a future height. The registry keeps superseded keys for `PQ_EVIDENCE_RETENTION_HEIGHTS = 720,000` heights with a hard cap of 32 entries, so a verifier can still check historical votes without keeping an unbounded key history.

Under Ruleset v7, `stellereum wallet unjail` and `stellereum validator unjail` sign with the **cold withdrawal key**. The hot key cannot unjail a validator.

## Wallet signatures are a separate domain

A transaction signature and a "sign this message" wallet signature are not interchangeable:

- Transaction signatures cover the canonical transaction bytes and, when present, the chain id.
- The wallet signature standard builds an EIP-191-style preimage with the chain id bound in and returns a typed envelope (version, scheme, public key, signature).

`stellereum wallet sign` and `stellereum wallet verify` implement the message standard. A message signature can never be replayed as a transaction. The SDK documentation covers the wire format in [Wallets & signing](/sdk/wallets-and-signing).

## What post-quantum does and does not protect

**It protects against:** forgery by a cryptographically relevant quantum computer, classical signature downgrade, and cross-chain replay when chain binding is used.

**It does not protect against:** implementation bugs, side-channel leakage on the signing host, a compromised seed or passphrase, malicious RPC responses, or consensus bugs. The testnet has **no external audit**. Post-quantum cryptography raises the cost of one specific attack; it does not make the system safe by itself.

## Verification path at admission

For a PQ transfer, a node checks, in order:

1. The envelope magic, scheme and framing lengths.
2. That the signature length and public-key length match Falcon-512.
3. That `BLAKE3("STL_ADDR_V4" ‖ 0x02 ‖ pubkey ‖ salt)` equals `tx.from`.
4. That the Falcon signature verifies over the canonical signing message (with chain id if bound).
5. That the nonce is contiguous, the fee clears the floor, and `amount + gas_limit` is covered.
6. That duplicates, quotas and shard routing are valid.

Any failure is a refusal, not a fallback. That fail-closed shape is the point of a pure-PQ network.

## Next

Next, [Consensus & finality](/core-concepts/consensus-finality) turns Falcon votes into a quorum certificate. [Wallets & signing](/sdk/wallets-and-signing) covers the separate message-signing standard.
