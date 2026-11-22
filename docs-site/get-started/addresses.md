# Addresses

A Stellereum account address is **32 bytes**. It is not a 20-byte EVM address and it is not a hash of an Ed25519 key. It is a domain-separated hash of the Falcon-512 public key that controls the account.

## One key, one address

For a Falcon-512 wallet the address is:

```text
address = BLAKE3("STL_ADDR_V4" ‖ 0x02 ‖ falcon_public_key ‖ salt)
```

| Input | Value |
| --- | --- |
| Domain | ASCII `STL_ADDR_V4` |
| Scheme id | `0x02` (Falcon-512) |
| Public key | Falcon-512 public key bytes (897 bytes) |
| Salt | 16 bytes; the default is 16 zero bytes |

The public key is part of the preimage, so the address commits to the key. There is no separate "create account" transaction: the first spend reveals the public key, the node derives the address, checks that it matches `tx.from`, and pins the key for later spends.

::: danger A rotated key is a new address
Because the address commits to the Falcon public key, you cannot rotate a wallet key and keep the same address. Generate a new key, derive the new address, and move the funds explicitly. A validator has a separate 32-byte **validator id** (voter id) that stays stable while its hot voting key can rotate under the PQ key registry; that is a validator-specific mechanism, not a wallet address rotation.
:::

## Deriving the address

The CLI derives the address whenever it needs it. To print the address for a seed without sending anything:

```sh
stellereum wallet sign \
  --scheme falcon \
  --falcon-seed "$STELL_SENDER_SEED" \
  --message "derive my testnet address" \
  --chain-id 5757
```

The `Address:` field is the PQ address. `wallet send-pq` performs the same derivation for `tx.from`; if the funded address and the signing seed disagree, admission fails for insufficient balance rather than silently spending a different account.

::: warning Do not use the legacy Ed25519 helper for a Falcon wallet
`wallet address --from-key` follows the legacy Ed25519 derivation, not the Falcon-512 PQ derivation. It is not a way to derive a Stellereum PQ address. Use `wallet sign --falcon-seed` (or the SDK's PQ address helper) instead.
:::

## Display formats

All three spellings below refer to the same 32 bytes. RPC methods accept the hex form everywhere; the branded form is for humans and UI.

| Form | Example | Rules |
| --- | --- | --- |
| Raw hex | `1e6281…8920a` | Exactly 64 hex characters; `0x` prefix is optional |
| Branded | `Stl57…` | Base58 body plus a 4-byte BLAKE3 checksum; prefix `Stl57` is case-insensitive; homoglyphs are rejected |
| masterchain routing form | `-1:<64 hex>` (or `0:<64 hex>`) | Explicitly addresses shard 0 in the TON-style routing scheme |

The `Stl57` prefix encodes "Stellereum L1, chain 5757". The checksum exists to catch typos before a transfer is signed; it is not a signature and it does not prove ownership.

## Routing: bare addresses are workchain addresses

Stellereum uses TON-style routing:

- **Shard 0 is the masterchain** and must be addressed explicitly as `-1:<address>` (or `0:<address>`).
- **A bare 32-byte address is a workchain address.** It never routes to the masterchain implicitly.
- Workchain addresses route by longest prefix match over the routing prefix; ties break by the smallest shard id.
- A split adds one prefix bit; a merge removes the deepest bit. Shard ids are never reused.

On the public network only shard 0 is live, so ordinary transfers use the same shard and do not need a prefix. If you are funding an account for staking or another masterchain-native operation, confirm which form the operation expects before sending. See [Sharding](/core-concepts/sharding) for the full rule.

## Address checklist

Before you fund an address:

- [ ] It is exactly 32 bytes (64 hex characters, `0x` optional) or a valid `Stl57…` string.
- [ ] It was derived from a Falcon-512 key you control, not from an Ed25519 helper.
- [ ] The seed or key file that controls it is backed up; there is no recovery service.
- [ ] For a faucet drip, you understand that the 50 STELL lifetime cap is per address.
- [ ] For a masterchain operation, you are using the form that operation expects.

## Next

Next, [Accounts & fees](/core-concepts/accounts-and-fees) covers the balance, nonce and fee rules for the address you just derived. [Wallets & signing](/sdk/wallets-and-signing) covers signatures that are not transactions.
