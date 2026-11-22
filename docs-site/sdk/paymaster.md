---
title: Paymaster (sponsored fees)
description: Paymaster v2 — a Falcon-512 sponsor pays the fee while a Falcon-512 user authorizes the action.
outline: deep
---

# Paymaster (sponsored fees)

A paymaster lets a funded **sponsor** pay the transaction fee for a user. The user authorizes the **action**; the sponsor authorizes the **fee** for that exact transaction. Both signatures are Falcon-512, and both are verified. The user's balance moves by the transfer amount only; the sponsor is debited the fee.

This is implemented in consensus as **Paymaster v2**. The legacy Ed25519 sponsor path is still parsed for compatibility, but the current pure-PQ verifier refuses it.

::: warning What "gasless" means here
The **user** pays no fee. The user's balance still moves by `amount` (and any payload value movement). The sponsor pays the fee, never the value. This is not a subsidy of the transfer amount.
:::

## What it changes

| | Plain transaction | Sponsored transaction |
| --- | --- | --- |
| Fee payer | `from` | sponsor |
| User balance change | `amount + fee` | `amount` only |
| User nonce | advances | advances on success and on attributable failure |
| Sponsor nonce | — | **never** advances |
| Signatures | one | two: sponsor first, user second |
| Wire format | `PQ1`/`SF1` envelope | `PQ1` envelope + trailing `SP1` grant |

## Wire format

No new field is added to `Transaction` or `Block`. The grant rides the existing `signature: Vec<u8>` field as a trailing suffix:

```text
inner_sig_blob ‖ bincode(SponsorAuthorization) ‖ len_be32 ‖ b"SP1"
```

Consequences:

- every pre-sponsor persisted block still decodes byte-for-byte;
- an old node rejects the longer blob at `Signature::from_slice` (64 bytes expected) — fail-closed;
- `compute_tx_hash` mixes in `SPONSOR_COMMITMENT_TAG` and the auth only when a sponsor envelope is present, so a legacy transaction hashes byte-identically to before.

### `SponsorAuthorization`

| Field | Meaning |
| --- | --- |
| `sponsor: [u8; 32]` | funded PQ account debited the fee |
| `max_fee_per_tx: u64` | hard ceiling on the fee execution may charge |
| `valid_until: u64` | Unix seconds; nothing is authorized after this |
| `allowed_targets: Vec<[u8; 32]>` | recipient allowlist; empty = any; capped at `SPONSOR_MAX_TARGETS` = 64 |
| `chain_id: u64` | replay domain, committed into both signatures |
| `sponsor_sig: Vec<u8>` | 666-byte Falcon-512 signature over `sponsor_message` (domain `SPONSOR_FEE_V1`) |
| `sponsor_scheme: Option<PqScheme>` | v2 requires `Falcon512` |
| `sponsor_pubkey: Option<Vec<u8>>` | 897-byte Falcon public key |
| `sponsor_salt: Option<[u8; 16]>` | salt used for the sponsor address; defaults to the zero salt |

`allowed_targets` carries `#[serde(default)]`, so older encodings that omit it decode as "no allowlist". The v2 scheme, public key and salt fields are optional on the wire but required by the current verifier.

## Signing order is load-bearing

1. The **sponsor signs first**. `sponsor_message` commits to the sponsor, the transaction core (`from`, `to`, `amount`, `gas_limit`, `nonce`, shards), the payload commitment, the priority bid, the caps, the allowlist and the chain id.
2. The **user signs second**. The PQ1 signing message commits to the action plus the **full grant**, including `sponsor_sig`.

Neither side can be swapped after signing: a grant cannot be grafted onto another transaction, and the grant cannot be replaced under the user's signature.

The node crate has the full-PQ constructor:

```rust
use stellereum::sharding::Transaction;

let tx = Transaction::sign_with_sponsor_falcon512(
    &user_key,              // Falcon-512 user key
    &sponsor_key,           // Falcon-512 sponsor key
    to,                     // [u8; 32]
    amount,
    gas_limit,
    nonce,
    source_shard,
    target_shard,
    payload,
    priority_fee_per_gas,
    max_fee_per_tx,
    valid_until,
    allowed_targets,
    chain_id,
);
```

Then submit the bincode bytes exactly like any other transaction:

```bash
curl -s -X POST http://127.0.0.1:8545 \
  -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_sendRawTransaction\",\"params\":{\"tx\":\"$TX_HEX\"}}"
```

::: warning SDK status
Neither `stellereum-sdk` nor `@stellereum/sdk` currently exposes a sponsor builder. Use the node crate above in a signer service, or implement the two preimages against the same fields. The older `Transaction::sign_with_sponsor` helper still compiles, but it produces a classical Ed25519 grant that the current pure-PQ verifier refuses.
:::

## Composition rules

Paymaster v2 requires a valid **post-quantum `PQ1` inner** envelope: explicit or implicit Falcon-512, with the sponsor's Falcon signature in the grant. A sponsor envelope on any of the following is refused fail-closed with `invalid sponsor grant`:

- a classical Ed25519 inner;
- a session-keyed (`SF1`) inner;
- an EVM (`EV`-family) inner;
- a malformed or truncated sponsor suffix.

Chain binding comes from the grant's `chain_id`, which is committed into both signatures. The inner PQ1 envelope may also carry a chain id.

An explicit **priority bid** in the struct field composes fine: it is not an inner envelope, and it binds both signatures and the fee math.

## Execution semantics

| Outcome | User balance | User nonce | Sponsor balance | Sponsor nonce |
| --- | --- | --- | --- | --- |
| Success | `- amount` (+ payload value) | `+1` | `- fee` | unchanged |
| Attributable failure, sponsor can cover | unchanged | `+1` | `- failure fee` | unchanged |
| Failure the sponsor cannot cover | unchanged | unchanged | unchanged | unchanged |
| Replay (user nonce mismatch) | unchanged | unchanged | unchanged | unchanged |

A sponsored failure is **not replayable**: the user nonce advances. A failure the sponsor cannot pay moves nothing — no fee, no nonce. The user's balance is never touched for the fee on any path. `fees_collected` credits the proposer the same fees regardless of payer, so value is conserved.

## Caps and anti-abuse

- `max_fee_per_tx` is checked against the fee execution will **actually** charge, not the declared limit. The F-01 charge is `max(min(gas_limit, gas_used + intrinsic), floor) + surcharge`; a below-floor declaration cannot smuggle an over-cap fee past the sponsor.
- Admission performs a **joint reservation**: `reserved[user] += amount` and `reserved[sponsor] += gas_limit + surcharge`. One funding backs exactly the slots it can jointly pay for.
- The per-sender quota stays on the user. There is deliberately **no per-sponsor quota** in v2; the sponsor's joint reservation across all sponsored transactions bounds total exposure.
- Four layers stop double-spend: admission reservation, block-admission simulation, commit-time re-check under the accounts lock, and wave scheduling (`Account(sponsor)` is an access key, so two transactions sharing a sponsor never land in one parallel wave).
- Mid-mempool revocation is economic: the proposer re-checks expiry, allowlist, cap and both funding legs against the **block timestamp**, then apply re-checks against committed state. A grant that expired or a sponsor that spent down is skipped, never hard-rejected.

### Admission errors

All are JSON-RPC `-32000`, prefixed `rejected: `.

| Condition | Message suffix |
| --- | --- |
| malformed suffix / unsupported inner composition | `invalid sponsor grant` |
| sponsor signature does not verify (both are required) | `invalid sponsor signature` |
| grant past `valid_until` | `sponsor grant has expired` |
| `to` not in `allowed_targets` | `sponsor grant does not cover this recipient (allowlist)` |
| fee above `max_fee_per_tx` | `sponsor grant per-tx fee cap does not cover this transaction's fee` |
| sponsor cannot cover the fee / no sponsor balance carried | `sponsor cannot pay the transaction fee` |

A sponsored transaction whose sponsor cannot cover the fee is refused **before pool entry** and never occupies mempool space.

## Wallet flow

1. The user constructs the action as usual: `to`, `amount`, `gas_limit`, `nonce`, shards, payload and priority bid.
2. User and sponsor agree off-chain on `max_fee_per_tx`, `valid_until`, `allowed_targets` and `chain_id`.
3. The sponsor signs the grant.
4. The user signs the action plus the full grant inside a PQ1 envelope.
5. Submit via `stell_sendRawTransaction`; watch `stell_getTransactionStatus`.
6. The receipt's `fee_charged` is what the **sponsor** paid. The user's balance moved only by the value.

Display the two caps to the user before they sign:

```text
fee payer:      0xSPONSOR…
max fee:        1,000,000 nano-STELL
valid until:    2026-11-22T18:00:00Z
recipients:     any / [0x…, 0x…]
chain id:       5757
```

## Fee estimation

For a sponsored Stellereum transaction, use `stell_estimateFee`. It simulates against a **clone** of the engine and returns the gas the call needs:

```json
{"jsonrpc":"2.0","id":1,"method":"stell_estimateFee",
 "params":{"from":"<hex>","to":"<hex>","amount":1000}}
```

```json
{"jsonrpc":"2.0","id":1,"result":{
  "gas_limit":1000,"estimated_fee":1000,"base_fee":1000,
  "source_shard":0,"target_shard":1,"is_cross_shard":true,
  "gas_budget":5000000,"gas_ceiling":5000000,"status":"ok"
}}
```

The simulation ceiling is fixed at **5,000,000** gas. `max_gas` may only lower the budget; a value above the ceiling or below the 280,000 basic-transfer floor is refused (`-32602`). The endpoint is unauthenticated but has its own tight per-IP budget (**5 req/s**) because it clones the whole engine.

Set `max_fee_per_tx` from this answer, not from `eth_estimateGas`. The EVM estimate is an admission floor, not execution metering.

## Non-goals (v2)

- **No per-epoch or total on-chain sponsor budget.** A sponsor that signs many grants can be drained up to `(#grants × cap) + failures`. Sponsors must cap `max_fee_per_tx`, expire grants tightly, scope `allowed_targets` and stop signing when exposure is reached. This is the documented contract, not a bug.
- **No on-chain revocation registry.** "Revoke" means stop signing and spend down. In-flight grants remain valid until `valid_until`.
- **No composition with session keys or EVM inners.** A sponsored transaction uses a PQ1 inner, not `SF1` or an EVM carrier.
- **No sponsor nonce.** The sponsor account's nonce is snapshotted for the undo log and never incremented.
- **No guarantee of inclusion.** Admission is not finality. A sponsor grant can be valid and the transaction still be skipped if the sponsor's balance moves before the block.

## Next

Read [Session keys](/sdk/session-keys) for the other delegated-authority mechanism, and [Errors](/api/errors#transaction-rejection-strings) for the exact sponsor refusal strings.
