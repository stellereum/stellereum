# Stellereum privacy path

Transparent is the base layer. Privacy is an **opt-in per-transaction path**,
not a consensus flip: three first-class RPC arms over the existing
confidential opcodes (`SysCallConfidentialShield`,
`SysCallConfidentialTransfer2`, `SysCallConfidentialUnshield`). No new
curves, no new proofs — Pedersen commitments + enforced range proofs,
Ristretto stealth addresses, viewing keys, all from `src/crypto_privacy.rs`.

## Hidden vs visible, per transaction type

| Tx type | Visible on chain / in explorer | Hidden |
| --- | --- | --- |
| `transparent` | sender, recipient, amount, fee limit, nonce | — (nothing) |
| `confidential` (Transfer2) | sender, recipient (plain or one-time stealth), inner confidential fee, input/output **counts**, commitment hex, per-input spent flags | amounts, blindings |
| `confidential-shield` (entry) | sender, commitment, **native amount entering escrow**, fee limit, nonce | blinding (the coin's spend secret) |
| `confidential-unshield` (exit) | sender, input count, **total released**, fee limit, nonce | blindings (amounts are public **by design** at exit — the verifier recomputes each commitment from the revealed opening) |

Rules that never bend: the **sender is always public** (`tx.from` + nonce +
public gas payment) — there is no RingCT and no anonymity set (audit KI-05).
V1 (`SysCallConfidentialTransfer`, equation-only, no range proofs) **stays
refused** on the block path; only range-proof-enforced Transfer2 executes
(audit K-09). Double-spend is refused by the committed `spent` set (consumed
commitment bytes — there is no separate nullifier field; membership IS the
flag), checked together with the `owned` map: a Transfer2 replay fails with
`DoubleSpend`, an exited coin fails re-exit at the ownership gate with the
coin remaining in `spent` as backstop (audit K-10).

## How-to (prepare-only where money moves; reads direct)

All three are exposed through `stell_*` (see `stell_nativeApiManifest`).
The two money-moving arms **prepare** — they return the exact payload to
sign plus the fee **before** signing, and never mutate state. There is **no
public submit arm**: submit the signed payload with `stell_sendRawTransaction`.

```jsonc
// 1. Enter + transfer: native -> shielded coin to `to` (address or stealth {view_pub, spend_pub}).
//    Shows gas_limit (1.75x confidential surcharge) and confidential_fee BEFORE signing.
{ "to": "<hex|stl57|{view_pub,spend_pub}>", "amount": "50000", "fee": "100", "sender": "<hex>" }
// => stell_shieldedTransfer
//    gas: SHIELD 3_500 + Transfer2 (3_500 base + 1_750/commitment + 44/bit).
//    1-in/1-out at 32-bit widths: 3_500 + 9_816 = 13_316. The `openings`
//    array holds the spend secrets — store like private keys.

// 2. Read: sum spendable shielded balance for a viewing key over caller-held payloads.
{ "viewing_key": "<64-hex private>", "payloads": [{ "ephemeral_pub": "..", "ciphertext": "..", "nonce": ".." }] }
// => stell_shieldedBalance
//    Pure read: decrypts each payload, recomputes its commitment, checks the
//    committed `owned` map + `spent` nullifier set. Only unspent owned coins sum.

// 3. Exit: shielded coin back to transparent. `to` MUST equal the signer.
{ "to": "<hex>", "amount": "50000", "sender": "<hex>",
  "inputs": [{ "commitment": "..", "amount": "50000", "blinding": ".." }] }
// => stell_unshield
//    gas: 3_500 base + 525/input (max 64 inputs per tx).
```

## Viewing-key warning

The viewing key in `stell_shieldedBalance` is a **secret**: it decrypts every
payload ever encrypted to it — past and future, with no forward secrecy. It
is parsed, used, and dropped inside the call, never logged and never echoed
(only the public half is returned). Anyone holding it sees your amounts.
A wrong key decrypts nothing and sums zero — silence, not an error.

## Explicit non-goals

- **No private-by-default.** Transparent stays the base; every shielded step
  is opt-in per transaction.
- **No anonymity.** Sender, recipient slot, fee, commitments, and counts are
  public. Only amounts/blindings hide. Do not use this to evade sanctions,
  taxes, or lawful audit — the viewing-key flow exists so compliance can be
  demonstrated without surrendering spend authority.
- **No new cryptography.** No new curves, no new proof systems, no RingCT,
  no anonymity set. Range enforcement is never weakened (V1 stays refused).
- **No shielded balances RPC.** `stell_shieldedBalance` sums what the caller
  can already open with its viewing key against exactly what the chain
  stores (`owned` outputs, the `spent` nullifier set, `total_fees`) — it
  invents no tracking and reveals nothing by itself.
- **No submit arm.** Prepare-only endpoints; signing and submission stay with
  the wallet via `stell_sendRawTransaction`.
