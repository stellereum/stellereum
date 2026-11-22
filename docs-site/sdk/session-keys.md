---
title: Session keys
description: Delegated session keys — scoped, budgeted, expiring authority with terminal revocation.
outline: deep
---

# Session keys

A session key is a **delegated Falcon-512 key** that can sign transactions on
behalf of a master account, within limits the master signed. It is the closest
thing Stellereum has to a "delegated session" or an "agent key":

- the session key can submit transactions **as the master** (`tx.from` is the
  master address);
- the master's nonce, balance and fee apply;
- the grant constrains **scope**, **cumulative gas budget**, **expiry** and
  **value per transaction**;
- revocation is **terminal**.

The session key never holds funds. Compromise is bounded by the remaining
budget and the grant's expiry, not by the master's whole balance.

::: warning Not a multisig
A session key is a single delegated key with policy limits, not a threshold
account. Stellereum has no user-level multisig; the only "multisig" in the tree
is the bridge relayer 2/3 quorum, which is not user custody.
:::

## Grant fields

| Field | Meaning |
| --- | --- |
| `master_address: [u8; 32]` | the account whose authority is delegated (`tx.from`) |
| `session_pubkey: [u8; 32]` | the session key's derived address |
| `valid_until: u64` | Unix seconds; nothing is authorized after this |
| `max_gas_spend: u64` | cumulative gas budget for the whole grant |
| `gas_spent: u64` | gas consumed by transactions that **applied** (excluded from the master's signature) |
| `scope: u64` | bitmask of allowed operation classes |
| `max_value_per_tx: u64` | per-transaction value cap |
| `chain_id: u64` | replay domain |
| `master_signature: Vec<u8>` | Falcon-512 over the grant message |
| `master_pubkey` / `session_pubkey_bytes` | required by the node verifier |

`gas_spent` is deliberately **not** signed. The master authorizes a budget, not
a running counter; the registry owns the counter.

## Scopes

| Bit | Constant | Covers |
| --- | --- | --- |
| `1 << 0` | `SCOPE_TRANSFER` | plain native value transfers (empty payload) |
| `1 << 1` | `SCOPE_SVM_PAYLOAD` | any SVM/contract payload |
| `1 << 2` | `SCOPE_ACTOR_SEND` | actor mailbox sends (in addition to `SCOPE_SVM_PAYLOAD`) |
| all bits | `SCOPE_ALL` | everything |

The node computes the **required** scope from the transaction:

```text
empty payload                          -> SCOPE_TRANSFER
payload with SysCallActorSend          -> SCOPE_SVM_PAYLOAD | SCOPE_ACTOR_SEND
any other non-empty payload            -> SCOPE_SVM_PAYLOAD
```

The grant must cover **every** required bit. `SCOPE_TRANSFER | SCOPE_SVM_PAYLOAD`
does not allow an actor send. Scope bits are frozen; new bits are appended so
old grants keep their meaning.

## The grant message

```text
"STELL_SESSKEY_V1"        (17 B)
‖ chain_id               (u64 BE, 8 B)
‖ master_address         (32 B)
‖ session_pubkey         (32 B)
‖ valid_until            (u64 BE, 8 B)
‖ max_gas_spend          (u64 BE, 8 B)
‖ scope                  (u64 BE, 8 B)
‖ max_value_per_tx       (u64 BE, 8 B)
```

`gas_spent` is excluded. The domain string separates this signature from a
transaction, a message and a paymaster grant.

## SF1 envelope

A session-signed transaction uses the `SF1` framing in the `signature` field:

```text
session_signature(666) ‖ "SF1" ‖ bincode(SessionKeyAuthorization)
```

The authorization carries the grant, both public keys and the master
signature. `tx.from` is the **master** address. The session key signs the
transaction base plus a `SESSION` commitment (the grant is bound into the
message and the transaction hash), not a `CHAIN_ID` commitment; the chain id
lives in the grant.

## Rust SDK

```rust
use stellereum_sdk::{
    FalconKeypair, SessionGrant, TxBuilder, SCOPE_TRANSFER,
};

let master = FalconKeypair::load_key_file(std::path::Path::new("master.json"))?;
let session = FalconKeypair::generate()?;

let grant = SessionGrant::new(
    &master,
    session.public_key(),
    1_800_000_000,     // valid_until
    5_000_000,         // cumulative gas budget
    SCOPE_TRANSFER,    // scope
    100_000_000,       // max value per tx, nano-STELL
    5757,              // chain id
)?;

assert!(grant.verify_master());
assert_eq!(grant.remaining_gas(), 5_000_000);
assert!(grant.grants_scope(SCOPE_TRANSFER));
```

Sign a delegated transfer:

```rust
let signed = TxBuilder::transfer([0x22; 32], 1_000)
    .nonce(master_nonce)          // the MASTER's nonce
    .sign_with_session(&session, &grant)?;
signed.verify()?;
```

`SessionGrant` also exposes `.encode()` / `.decode()` for the bincode wire
form.

## Preparing a grant over RPC

`stell_sessionKeyRegister` is a **prepare** method: it returns the exact
transaction and the exact bytes the master must sign. It does not write state.

```json
{"jsonrpc":"2.0","id":1,"method":"stell_sessionKeyRegister","params":{
  "session_pubkey":"<64 hex>",
  "master":"<64 hex>",
  "valid_until":1800000000,
  "max_gas_spend":5000000,
  "scope":1,
  "max_value_per_tx":100000000
}}
```

The result carries:

- `transaction.op` = `SysCallPublishSessionGrant` and
  `transaction.args.grant`;
- `grant_message` (`0x…`) and `grant_message_hex` — the exact preimage above;
- `chain_id`, `session_pubkey`, `master`, the policy fields and a `sign_hint`.

Put the master's Falcon signature in
`transaction.args.grant.master_signature`, then submit the transaction through
`stell_sendRawTransaction`.

Validation is fail-closed:

| Refusal | Code |
| --- | --- |
| zero session or master address | `-32003` |
| `max_gas_spend == 0` | `-32003` |
| `scope == 0` | `-32003` |
| `valid_until == 0` | `-32003` |
| session already revoked | `-32003` |
| session already registered to another master | `-32003` |

::: warning FULL-PQ schemes
The node's session policy requires **both** the master and session credentials
to be post-quantum. A grant carrying classical Ed25519 scheme ids is refused
with `invalid session key delegation grant`. Use Falcon-512 key material (as
the SDK does). The native prepare template labels schemes `Ed25519` by
default; a wallet must replace them with the real Falcon schemes before
submitting.
:::

## Budget

The budget is **cumulative gas**, not a number of transactions:

```text
gas_spent += gas actually consumed by an APPLIED transaction
remaining  = max_gas_spend - gas_spent
```

- A refused transaction costs the grant nothing.
- A transaction is admitted only if its **declared `gas_limit`** fits in
  `remaining_gas()`. This is a conservative reservation: the grant is charged
  what the transaction actually consumes on apply, but it must be able to
  cover the declared limit at admission.
- Admission and the proposer filter carry an **in-block spend overlay**, so two
  transactions of one grant in the same block cannot each pass against the same
  remaining budget.
- Budget exhaustion is `session key delegation has been revoked or has no
  remaining budget` (a single message for both cases, by design).

Read it from committed state:

```json
{"jsonrpc":"2.0","id":1,"method":"stell_sessionBudget",
 "params":{"session":"<64 hex session pubkey>"}}
```

```json
{"jsonrpc":"2.0","id":1,"result":{
  "registered":true,
  "revoked":false,
  "valid_until":1800000000,
  "scope":1,
  "max_gas_spend":5000000,
  "spent":250000,
  "remaining_gas":4750000,
  "master":"<64 hex>",
  "chain_id":5757
}}
```

An unknown key answers `registered:false` with all zeros — not an error.

## Expiry

`valid_until` is checked against a **deterministic** clock:

- the admission context's time at mempool entry;
- the **block timestamp** at propose selection and at execution.

It is never the local wall clock inside consensus execution. A grant that
expires between admission and inclusion is skipped by the proposer and refused
at apply.

Expired is `session key delegation has expired`.

## Revocation

`stell_sessionKeyRevoke` prepares `SysCallRevokeSession`:

```json
{"jsonrpc":"2.0","id":1,"method":"stell_sessionKeyRevoke",
 "params":{"session_pubkey":"<64 hex>","master":"<64 hex>"}}
```

Only the master that owns the key may revoke it. A named `master` that differs
from the registry's master is `-32003`; an unknown key is `-32004`.

Revocation semantics:

- **Terminal.** `revoked: true` is never cleared. Re-registering the same
  session key is refused with `this session key was revoked: a revocation is
  terminal`.
- **Tombstones for unused keys.** The registry is lazy: a key that never
  applied a transaction has no record, and `SysCallRevokeSession` refuses an
  unknown key so nobody can pre-tombstone a victim by guessing a public key.
  A master who wants to revoke an unused grant uses the preventive tombstone
  path; it is stored like any record and is part of the committed digest.
- **Committed.** The registry, including `revoked`, is in the state commitment
  digest. A node that revoked a key cannot silently agree with one that did
  not.

A revoked key is refused at admission with
`session key delegation has been revoked or has no remaining budget` and again
at propose/apply.

## Transaction policy checks

At admission and again at execution, the node checks:

1. both schemes are post-quantum;
2. `master_address == tx.from`;
3. the master signature verifies;
4. `now <= valid_until`;
5. the grant covers `required_scope(tx)`;
6. `tx.amount <= max_value_per_tx`;
7. `tx.gas_limit <= remaining_gas()`.

A failure is one of four typed errors:

| Error | Message |
| --- | --- |
| `Expired` | `session key delegation has expired` |
| `Revoked` / `BudgetExhausted` | `session key delegation has been revoked or has no remaining budget` |
| `OutOfScope` | `session key delegation does not cover this transaction` |
| `BadGrant` | `invalid session key delegation grant` |

## Registry reads

`stell_sessionKeys` lists the committed registry:

```json
{"jsonrpc":"2.0","id":1,"method":"stell_sessionKeys","params":{"master":"<64 hex>"}}
```

```json
{"jsonrpc":"2.0","id":1,"result":{"session_keys":[…],"count":1}}
```

Omit `master` to list all. Each entry carries the master, policy fields,
`gas_spent`, `revoked` and the session key.

## Design guidance

- **Scope tightly.** A payment agent needs `SCOPE_TRANSFER`, not
  `SCOPE_SVM_PAYLOAD`. A contract bot needs `SCOPE_SVM_PAYLOAD` and should not
  be able to move native value outside the contract.
- **Cap value per transaction, not just gas.** `max_value_per_tx` is the only
  per-transaction value bound.
- **Budget for the worst case.** Admission reserves the declared `gas_limit`;
  a session that declares a huge limit can starve itself even if execution is
  cheap.
- **Expire aggressively.** `valid_until` is the only bound on an unused but
  compromised key.
- **Revoke, do not rotate in place.** Revocation is terminal and the session
  address cannot be reused. Mint a new session key instead.
- **Watch `remaining_gas`.** Poll `stell_sessionBudget`; a key that exhausts its
  budget fails exactly like a revoked key.

## Limits and non-goals

- No per-operation counter, rate limit or allowlist of recipients. The grant
  binds scope, total gas, expiry and per-transaction value only.
- No partial revocation or budget top-up. A grant is immutable; mint a new one.
- No delegation chains. A session key cannot mint another session key.
- No session-key composition with the paymaster. A sponsored transaction must
  use a PQ1 inner envelope, not `SF1`.
- The master's funds remain fully at risk if the session key is used within
  its caps. Budget and scope bound the damage; they do not eliminate it.

## Next

Continue with [Paymaster](/sdk/paymaster) for fee delegation, or [Errors](/api/errors#transaction-rejection-strings) for the admission messages. [Rust SDK](/sdk/rust#session-grants) has the builder API.
