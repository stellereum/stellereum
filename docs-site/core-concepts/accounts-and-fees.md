# Accounts & fees

Every Stellereum account is a 32-byte key with a balance and a nonce, and every transaction that touches it pays gas in nano-STELL. This page defines the account object, the nonce and fee rules, and the failure behavior you need to budget for. Read it before you build a wallet, a faucet or a contract that moves value.

## The account object

A Stellereum account is a 32-byte key with state:

| Field | Meaning |
| --- | --- |
| `address` | 32-byte account key |
| `balance` | `u64` in nano-STELL |
| `nonce` | Next executable transaction number |
| `code`, `code_hash` | Contract code and its hash, when the account is a contract |
| `storage_root` | Commitment to contract storage |
| `inbox`, `outbox` | Actor messages for native application flows |
| `scheme` | Signature scheme bound to the account (Falcon-512) |
| `pubkey_hash` | Handle to the registered PQ public key |

A missing account reads as `{"balance":"0","nonce":0}`. There is no distinction between "never funded" and "funded then drained" in the basic read; both have zero balance and zero nonce until a transaction changes them.

1 STELL = **1,000,000,000 nano-STELL** (9 decimals). All RPC amounts are decimal strings of nano-STELL, not JSON numbers. Do not parse them as floats.

## Nonces

Every transaction carries an explicit `nonce`. It must be contiguous with the sender's executable head:

- The next valid nonce is the account's current nonce, or the first gap after the nonces already pooled for that sender.
- A transaction may arrive slightly out of order. A sender can buffer nonces up to **4** past its executable head; a gap larger than that is refused at admission with a nonce-gap error.
- A far-future nonce that cannot execute is not held forever. Unverified activation-buffer entries have a short TTL, and pooled future nonces are evicted rather than pinning the pool.

In practice: if you submit nonce `N` and then `N+1`, and the first is still pending, the second can be buffered. If you submit `N+10`, expect a refusal. Query the nonce from `stell_getBalance` (the result includes `nonce`) or let the CLI query it for you.

## Fees

Stellereum charges gas in nano-STELL. A transaction declares a `gas_limit`; admission requires the sender to cover `amount + gas_limit` at the live base fee.

| Parameter | Value / source |
| --- | --- |
| Basic transfer gas | **`GAS_BASIC_TRANSFER = 280,000`** gas |
| PQ activation surcharge | **45,000 gas** when a transaction carries a raw PQ public key |
| Admission floor | Read from `stell_baseFee` |
| Governed floor | `max(STELL_MIN_GAS_LIMIT, governance min_gas_limit)`; the same floor prices admission and proposal validation |
| Fee split | 50% burn, 30% proposer, 20% staking pool (Ruleset v7) |

`stell_baseFee` returns the current floor:

```json
{"jsonrpc":"2.0","id":1,"result":{"base_fee":"…"}}
```

A wallet must set `gas_limit` at or above the live floor; a transaction below the floor is refused at admission, not included and failed. `stell_estimateFee` runs the transaction against a clone of state and reports the expected cost and target shard. `stell_estimateFee` is expensive by design and is rate-limited; cache the result briefly instead of estimating on every keystroke.

The CLI's `wallet send-pq` sets the gas limit to `GAS_BASIC_TRANSFER + 45,000` and leaves the priority fee at zero. A transfer that only moves value does not execute contract code.

## The F-01 failure rule

A transaction that is **included and fails still pays**. This is deliberate: execution work is real even when the result is a failure, and free failure would let an attacker burn block space indefinitely.

The exact cases:

| Case | Fee | Nonce | State |
| --- | --- | --- | --- |
| Refused at admission (bad signature, below floor, malformed) | **Nothing** | Unchanged | Unchanged |
| Replay or nonce gap (not attributable to an executed attempt) | **Nothing** | Unchanged | Unchanged |
| Included, fails, sender can cover the charge | `max(gas_limit, floor) + surcharge` | **+1** | Failure is recorded; no partial effect survives |
| Included, fails, sender cannot cover the charge | **Nothing moves** | Unchanged | No partial state change |

The last row is the "no-pay, no-state-change" rule: if the sender cannot cover the failure charge, the protocol does not apply a half-finished effect. A failed transaction never leaves partial writes behind; contract state changes are rolled back.

::: warning Budget for failure
A transaction that reverts consumes its fee. Do not treat `gas_limit` as a refundable deposit. If an operation is marginal, estimate it first and leave headroom above the floor.
:::

## Reading balances and fees

```sh
RPC=https://rpc.stellereum.org

# balance and nonce
curl -sS "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_getBalance","params":{"address":"<64 hex>"}}'

# current admission floor
curl -sS "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_baseFee","params":[]}'
```

`stell_getBalance` serves the masterchain account state. For a proof-carrying balance read, use `stell_getBalanceSpv`, which returns a Merkle proof and the state root so a light client can verify the value against a quorum-certified header.

## What an account cannot do

- **No secp256k1 owner.** An EVM address is not a Stellereum account. A binding can route an EVM-shaped address to a PQ account, but the PQ signature remains the authority.
- **No implicit masterchain routing.** A bare address is a workchain address; masterchain-native operations must use the explicit form. See [Addresses](/get-started/addresses).
- **No recovery.** There is no social recovery, no admin key, and no way to reverse a finalized transfer. A lost Falcon seed is a lost account.

## Next

Continue with [Consensus & finality](/core-concepts/consensus-finality) to see how a funded account becomes a finalized block, or run the [Quickstart](/get-started/quickstart) for a complete transfer. [Addresses](/get-started/addresses) covers derivation if you still need a key.
