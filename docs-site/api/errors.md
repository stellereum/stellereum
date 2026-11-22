---
title: Errors
description: JSON-RPC codes, faucet refusal reasons, transaction rejection strings and HTTP statuses.
outline: deep
---

# Errors

Stellereum distinguishes **transport/protocol errors** (JSON-RPC negative
codes) from **state refusals** (`-32000` / `-32003`) and from **answers that
look like errors but are data** (`{"success":false}` from a get-method,
`{"status":"failed"}` on a receipt). Use it to map a code or message to the
layer that refused it and the fix that clears it.

::: tip First rule
Read the `message`, not just the code. Two different refusals can share a code,
and the prefix tells you which layer refused:

- `rejected: …` — mempool admission;
- `propose failed: …` / `vote failed: …` / `execute failed: …` — governance;
- `faucet …` — faucet policy;
- `simulation …` — fee estimation.
:::

## JSON-RPC codes

| Code | Name | Meaning | Retry? |
| --- | --- | --- | --- |
| `-32700` | parse error | body is not JSON | no |
| `-32600` | invalid request | no `method`, wrong shape, empty/oversize batch, body > 1 MiB | no |
| `-32601` | method not found | unknown method, or a disabled feature | no |
| `-32602` | invalid params | malformed/missing/invalid parameter or wire bytes | no |
| `-32000` | chain error | admission, policy, faucet, budget, simulation | usually no |
| `-32001` | unauthorized | missing/invalid token or fail-closed arm | no |
| `-32003` | refused by state | committed state refuses the native operation | no |
| `-32004` | not available | object/height/proof not known to this node | maybe another node |
| `-32010` | no epoch key | MEV committee DKG incomplete | yes, later |
| `-32011` | sealed tx refused | stale epoch, duplicate, quota, full pool | sometimes |

### `-32602` — invalid params

Typical messages:

```text
missing address
missing tx
bad hex: <detail>
decode: <detail>
transaction too large
missing token/account
missing validator
missing height
missing proposal id
missing or invalid voter address
invalid amount: must be a positive integer
invalid address: <detail>
unknown subscription type: <x>
missing subscription type
missing subscription id
missing 'tx_hash' or 'contract' parameter
invalid contract address: <detail>
```

A parameter that is present but unparseable is often treated as **missing**
(for example `stell_tokenBalance` uses `and_then(parse_hash)`), so a typo and
an absent field can produce the same message. Rebuild the request from the
SDK rather than patching bytes.

### `-32000` — chain error

The message carries the layer's exact refusal. Common families:

| Prefix / message | Layer |
| --- | --- |
| `rejected: <mempool reason>` | mempool admission |
| `invalid transaction signature` | signature verification |
| `faucet …` | faucet policy |
| `propose failed: …` | governance propose |
| `vote failed: …` | governance vote |
| `execute failed: …` | governance execute |
| `deploy contract failed: …` | contract preview |
| `insufficient funds to transfer value: …` | contract call preview |
| `estimate-fee budget exhausted for this IP …` | fee estimator |
| `simulation out of gas` | fee estimator |
| `simulation reverted: …` | fee estimator |
| `subscription limit reached (4096 live subscriptions)` | subscriptions |
| `per-client subscription limit reached (64 live subscriptions for this client)` | subscriptions |

### `-32001` — unauthorized

| Message | Cause |
| --- | --- |
| `unauthorized: missing or invalid API token` | gated write without/wrong token |
| `unauthorized: stell_mempoolDump is disabled when auth_token is not configured` | fail-closed arm with no token |
| `faucet is enabled but STELL_FAUCET_TOKEN is not set; refusing to dispense` | fail-closed faucet |
| `unauthorized: missing or invalid faucet token` | wrong faucet token |

Token-gated arms are listed in the [auth matrix](/api/json-rpc#auth-matrix).
Governance writes and contract previews require a token on **every** bind,
including loopback.

### `-32003` — refused by state

Only the native namespace uses this code systematically. It means committed
state refuses the operation before a transaction is even built:

- insufficient balance;
- paused token;
- thin bond / below minimum;
- withdrawal before cooldown;
- replayed bridge deposit;
- revoked session key;
- zero recipient / self-transfer / zero amount;
- allowance too low;
- mint past `max_supply`;
- not the token minter.

It is an error, never a silent downgrade. A native **read** returns `-32004`
for an unknown object, not a zero value.

### `-32004` — not available

| Message | Cause |
| --- | --- |
| `block not available yet` | height outside the 100-entry window |
| `block transactions not available yet (height not adopted/replicated on this node)` | this node has not committed/adopted the height |
| `requested height N is above this node's tip (M)` | future height on a shard query |
| `historical state is not available on this node` | unsupported `block_height` |
| `proposal not found` | unknown governance id |
| `token not found` | unknown token id |
| `unknown pair N` | orderbook pair |
| `unknown session key` | session registry |
| `unknown validator or no PQ key at that height: refusing` | PQ key query |

`-32004` is fail-closed: the node never substitutes a live value under a
historical label, and never invents an empty object for an unknown one.

### `-32010` / `-32011` — MEV path

| Code | Message | Meaning |
| --- | --- | --- |
| `-32010` | `no epoch key is available yet: the committee's key generation has not completed` | sealed transactions cannot be built yet; the plain path still works |
| `-32011` | `sealed transaction refused: …` | stale epoch, duplicate, per-sender quota, full pool |

`-32602 "refusing the sealed transaction: …"` is a **malformed frame** (bad
magic, truncation, invalid curve point, empty/oversize payload, reserved hash),
not a pool refusal.

## Transaction rejection strings

`stell_sendRawTransaction` returns `-32000` for admission refusals. The
message is `rejected: <reason>`.

| Reason | Meaning / fix |
| --- | --- |
| `invalid transaction signature` | wrong key, nonce, chain, fee preimage or framing. Rebuild and sign. |
| `transaction already in mempool` | **success** for submission; the exact bytes are pooled. The SDK treats it as success. |
| `sender exceeds mempool quota` | per-sender limit (default 1,024). Drain or consolidate. |
| `mempool is full and tx fee is too low` | raise the fee/priority to displace an entry. |
| `sender cannot pay amount + gas_limit` | fund `amount + gas_limit + 45,000` (explicit PQ1). |
| `offered fee is below the base fee` | raise `gas_limit` to `required_fee_for_tx`. |
| `nonce gap: sender can execute X, got Y (fill the gap first)` | send the missing nonce first. |
| `session key delegation has expired` | mint a new grant with a later `valid_until`. |
| `session key delegation has been revoked or has no remaining budget` | same message for revocation and exhaustion; mint a new session. |
| `session key delegation does not cover this transaction` | scope or `max_value_per_tx` too narrow. |
| `invalid session key delegation grant` | bad master signature or non-PQ scheme. |
| `sponsor grant has expired` | sponsor `valid_until` passed. |
| `sponsor grant does not cover this recipient (allowlist)` | `to` not in `allowed_targets`. |
| `sponsor grant per-tx fee cap does not cover this transaction's fee` | raise `max_fee_per_tx` or lower the fee. |
| `invalid sponsor grant` | malformed suffix or unsupported inner composition. |
| `invalid sponsor signature` | both sponsor and user signatures are required. |
| `sponsor cannot pay the transaction fee` | fund the sponsor or drop the sponsor. |
| `malformed transaction: <detail>` | bad wire shape. |
| `transaction too large: estimated N wire bytes exceeds block cap M` | the transaction can never fit a block; split it. |
| `transaction carries N proof units, exceeding block cap M` | same, proof-unit cap. |

### Chain-binding refusals

| Message | Meaning |
| --- | --- |
| `rejected: unbound transaction refused ... re-sign the transaction bound to chain_id <id>` | phase-3 admission; bind the envelope |
| `Transaction chain_id mismatch: chain id A does not match this chain (B)` | signed for another chain |
| `Pure PQ mode: classical non-PQ transactions rejected, submit with PQ1 envelope` | not a `PQ1`/`SF1` envelope |

Unbound transactions are currently **admitted and metered** (phase 1):
`stell_unbound_tx_total` increments and the node logs
`[mempool] admitting UNBOUND …`. Treat a non-zero counter as “replayable
traffic this node accepted”.

### EVM-specific refusals

EVM errors carry a machine-readable `data.reason`.

| `data.reason` | Meaning |
| --- | --- |
| `full-pq-admission` | the EVM sender has no on-chain PQ binding |
| `pq-carrier-authorization-required` | `data` names the Falcon bytes to sign |
| `evm-binding-conflict` | the EVM address is already bound to another PQ account (first claim wins) |
| `evm-contract-execution-unsupported` | contract creation or calldata; there is no EVM interpreter |
| `evm-recipient-unbound` | the recipient EVM address has no PQ binding |

`eth_sendRawTransaction` without a carrier cannot move value. Bind the address
with proof of possession, then submit a carrier (or use
`stell_evmCarrierSubmit`).

## Faucet refusal reasons

The faucet has three ingress paths with slightly different policy:

- **`stell_faucet` (JSON-RPC, token-authenticated):** drip clamped to 2 STELL
  (or `STELL_FAUCET_DRIP_STELL`), per-IP budget **20/hour**, lifetime cap
  **50 STELL** per address. It does **not** apply the public 45-minute
  per-address cooldown.
- **`POST /api/faucet/:address` (gateway, token-authenticated):** mirrors the
  JSON-RPC gate and policy; no 45-minute cooldown.
- **`POST /api/faucet-public/:address` (public, captcha-gated):** fixed 2 STELL
  drip, **45-minute per-address cooldown**, **20/hour per IP**, lifetime cap
  **50 STELL**. When Cloudflare Turnstile is configured, a missing token is
  `400` and a rejected token is `403`; an unconfigured captcha off loopback is
  `503`.

All paths are fail-closed.

::: warning 50 STELL is an onboarding drip, not validator capital
The default lifetime cap is **50 STELL** per address. A validator bond needs
**1,100 STELL**. The faucet cannot fund a validator; use a network-admin
transfer or a faucet deliberately configured with a higher
`STELL_FAUCET_LIFETIME_CAP_STELL`.
:::

| Message | Code / HTTP | Meaning |
| --- | --- | --- |
| `faucet is disabled on this node` | `-32601` / 404 | `STELL_FAUCET` is not `1`/`true` |
| `faucet is enabled but STELL_FAUCET_TOKEN is not set; refusing to dispense` | `-32001` / 503 | enabled without a token; operator error |
| `unauthorized: missing or invalid faucet token` | `-32001` / 401 | wrong/missing token |
| `missing address` | `-32602` / 400 | no address |
| `invalid address: …` | `-32602` / 400 | not 32 bytes or malformed `-1:`/`N:` prefix |
| `invalid amount: must be a positive integer` | `-32602` / 400 | `amount: 0` |
| `faucet limit reached for this address` | `-32000` / 429 | lifetime cap spent |
| `public drip cooling down for this address, retry in N seconds` | `-32000` / 429 | public 45-min cooldown |
| `per-IP faucet budget exhausted for this hour` | `-32000` / 429 | 20 drips/hour from this IP |
| `faucet quarantined (fail-closed): …` | `-32000` / 503 | corrupt/unreadable persisted state |
| `faucet state could not be persisted: …` | `-32000` / 503 | durable write failed; no grant |
| `faucet on shard S cannot serve an address on shard T …` | `-32000` / 503 | sharded node, recipient on another shard; **burns no nonce/cap** |
| `faucet transfer rejected: …` | `-32000` / 503 | the signed transfer could not be admitted |

::: warning A drip is a pending transaction
`credited_nano` is the reserved amount; `tx_hash` is a **pending** transaction.
It can sit in the mempool without being included. Watch
`stell_getTransactionStatus` until `success`. The faucet does not write
balances; it signs an ordinary transfer from a genesis-funded account, so value
moves through consensus.
:::

### Which shard the drip lands on

- `-1:<hex>` (or `0:<hex>`) names a **masterchain** account → drip on shard 0.
  This is the form to fund for staking.
- a bare 64-hex address is a **workchain** address → drip on the shard selected
  by the routing prefix. A bare address **never** routes to the masterchain.
- `N:<hex>` names workchain shard N explicitly.

A sharded node's faucet serves **only its own shard's** recipients. A
cross-shard drip is refused at admission, never queued.

## HTTP gateway statuses

The read-only gateway (`STELL_EXPLORER_LISTEN`, default `127.0.0.1:8080`)
uses HTTP status codes:

| Status | Cause |
| --- | --- |
| `200` | success |
| `400` | bad address/parameter |
| `404` | unknown route, unknown `sub_id`, faucet disabled |
| `405` | `GET` on a POST-only faucet route |
| `429` | gateway rate limit, faucet cooldown/cap/IP budget |
| `503` | faucet transfer not admitted, faucet quarantined, readiness false |
| `500` | internal error |

All gateway routes set `access-control-allow-origin: *`. The JSON-RPC router
is nested at `/rpc` behind the same per-IP limiter (30 req/s default).

`GET /readyz` is special: it returns `200` with `{"ready":true,…}` or `503`
with `{"ready":false,"failed_checks":[…]}`. `failed_checks` values are
`no_peers`, `no_finality`, `finality_stalled`, `height_zero`,
`height_stalled`.

## Contract and get-method errors

`stell_runGetMethod` returns **answers**, not RPC errors, for execution
problems:

```json
{"success":false,"error":"too many arguments: at most 8","fuel_used":0}
{"success":false,"error":"pinned block height 500 exceeds current finalized height 194","fuel_used":0}
{"success":false,"error":"…","fuel_used":1234}
```

A malformed JSON request is still a JSON-RPC error.

`stell_callContract` (preview) uses `-32602` for ABI validation and parameter
errors, and `-32000` for insufficient value or execution failure. Its
`outcome.error` field is a string when the preview failed.

Contract source verification uses `verified:false` plus a machine-readable
`reason` for a legitimate negative result, and `-32602` for a missing
contract/bad address.

## Fee estimation errors

| Message | Cause |
| --- | --- |
| `estimate-fee budget exhausted for this IP (the simulation is expensive; retry shortly)` | 5 req/s budget exceeded |
| `simulation out of gas` | payload needs more than the simulation ceiling |
| `simulation reverted: …` | payload reverts |
| `max_gas above the estimate ceiling` (`-32602`) | asked for more than 5,000,000 |
| `max_gas below the basic transfer floor` (`-32602`) | asked for less than 280,000 |

The simulation ceiling is fixed at 5,000,000 gas. `max_gas` can only lower it.

## Subscription errors

| Message | Code |
| --- | --- |
| `unknown subscription type: <x>` | `-32602` |
| `missing subscription type` | `-32602` |
| `missing subscription id` | `-32602` |
| `subscription limit reached (4096 live subscriptions)` | `-32000` |
| `per-client subscription limit reached (64 live subscriptions for this client)` | `-32000` |

## Troubleshooting matrix

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `-32601` on a method you saw in docs | node older than docs, or feature disabled (`stell_faucet`, `eth_subscribe`) | check `stell_nativeApi` / version; upgrade |
| `-32001` on loopback | the arm is fail-closed without a token | configure `STELL_RPC_AUTH_TOKEN` (or the faucet token) |
| `-32004` for a height that exists | node outside the 512-header / 100-block window, or not adopted | query a node that serves it, or the indexer |
| `receipt` is `{"status":"pending"}` forever | tx is in **this** mempool but not included; stale nonce or fee | re-check `stell_baseFee`, nonce; re-submit |
| `receipt` flips `pending` → `unknown` | left this node's mempool without inclusion | re-submit; do not assume failure |
| `-32000 rejected: nonce gap` | missing earlier nonce | send the gap first |
| `-32000 rejected: sender cannot pay` | fee + value > balance | fund or lower amount |
| `Transaction chain_id mismatch` | signed for another chain | re-sign bound to 5757 |
| faucet `-32000` after one drip | 45-min public cooldown or 20/hour IP cap | wait, or fund from another source |
| gateway `429` on every call | per-IP 30 req/s limiter | back off; put a proxy in front for real auth |
| `-32003` on a native prepare | state refuses (balance, paused, bond, revoked session) | fix the precondition; it will not be silently downgraded |

## Next

Use the [JSON-RPC reference](/api/json-rpc) for the methods that raise these codes, and the [Rust SDK](/sdk/rust#common-errors) or [TypeScript SDK](/sdk/typescript#common-errors) for client-side mapping.
