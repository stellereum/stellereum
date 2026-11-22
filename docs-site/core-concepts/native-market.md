# Native market

Stellereum puts a market in the protocol: an on-chain central limit order book (CLOB), a primary market maker (PMM), scoped session keys for delegated trading, account objects that participate in native flows, and zkML opcodes that are re-execution checks, not zero-knowledge proofs.

This is testnet software. No external audit has been completed, and market parameters can change.

## Central limit order book

The CLOB is consensus state, not a separate matching engine. Orders are placed by transactions and only exist once a proposer includes them in a block. A read-only "depth" command that opens a local book would show a market that exists on no node, so the CLI queries the committed book over RPC instead.

| Property | Value |
| --- | --- |
| Pairs | `1` = STELL/USDT, `2` = STELL/TON, `3` = STELL/GRAM |
| Order placement gas | 1,200 |
| Order cancellation gas | 100 |
| Maximum match fills per order | 256 (Ruleset v7) |
| Read method | `stell_orderBook` with an optional `pair` id |

Order semantics:

- The SVM opcode has no separate "market order" variant. A market order is expressed as a limit order at a price that crosses on arrival. The CLI says so explicitly instead of pretending the two are identical.
- Cancellation is owner-only and has a read-only pre-check for the order's state, so an invalid cancel does not consume a full execution.
- Matching is bounded per order. An order that would require more than 256 fills is not silently allowed to consume an unbounded amount of block gas.
- An order is not a promise of liquidity. It is book state with the same finality rules as any other transaction: one finalized block is final.

Read the book:

```sh
curl -sS https://rpc.stellereum.org -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_orderBook","params":{"pair":1}}'
```

## Primary market maker

The PMM is a bonding-curve mint/redeem venue. It mints STELL against a USDT reserve and redeems STELL back into the reserve, with a depth cap and a redemption buffer so the curve cannot be drained to its last unit.

| Constant | Value |
| --- | --- |
| Base price | 250,000 micro-USD = **$0.25** |
| Depth cap | 125,000,000 STELL |
| Redemption buffer | 2,000 bps (**20%**) |

The current state is readable with `stell_pmmState`, which returns the price, minted amount, reserve, usable reserve, buffer, depth cap and governed buffer override. The PMM is a protocol venue, not an external market maker: its parameters are governance-visible and its arithmetic is consensus code.

::: warning PMM is not a price guarantee
The base price is a curve parameter, not a promise that STELL trades at $0.25 anywhere. Testnet PMM state is not a market price and must not be used as an oracle for real value.
:::

## Session keys

Session keys let a master account delegate a bounded trading authority without handing over the master key. A grant is a structured authorization, not a second account:

| Field | Meaning |
| --- | --- |
| `master_address` | Account that owns the funds |
| `session_pubkey` | Key allowed to act under the grant |
| `valid_until` | Expiry timestamp |
| `max_gas_spend` | Total gas budget across the grant |
| `gas_spent` | Consumed budget, committed by the transaction signature |
| `scope` | Bitmask of permitted operation classes |
| `max_value_per_tx` | Hard cap on native value per transaction |
| `chain_id` | Chain the grant is bound to |
| `master_signature` | Falcon-512 signature over the domain-separated grant message |

Design properties:

- **Bounded.** A session key cannot exceed its gas budget, its per-transaction value cap, its scope, or its expiry.
- **Chain-bound.** A grant minted for chain 5757 cannot be replayed on another chain.
- **Revocable.** The master can revoke a grant on chain; a revoked session is refused from then on, including a re-presented old grant.
- **Budgeted in consensus.** `gas_spent` is part of the committed authorization, so a session cannot reset its budget by replaying the grant.
- **Not a master key.** A session key cannot rotate the master key, withdraw the account, or exceed its scope.

Session budgets are queryable with `stell_sessionBudget`. See [Session keys](/sdk/session-keys) for the integration view.

## Account objects

A Stellereum account is more than a balance: it carries `code`, `storage_root`, an actor-style `inbox`/`outbox` for native messages, its signature scheme and a public-key handle. The native market uses these account objects for order ownership and session authority instead of inventing a parallel account system.

Two consequences:

1. **One identity for trading and contracts.** The same 32-byte account can own book orders, hold tokens, deploy a contract, and authorize a session key.
2. **Native messages are state, not logs.** Inbox/outbox entries can drive application flows; they are not a substitute for events, and they are committed with the account state.

## zkML: re-execution, not zero knowledge

The zkML opcodes are the place where marketing language most often outruns the code. In Stellereum:

- `SysCallVerifyZkMlReexec` (opcode 35) re-executes the model's forward pass and checks that the claimed public outputs match.
- `SysCallVerifyZkMlAttestation` (opcode 38) additionally checks a registered model spec and a **BLAKE3 Merkle tree over every neuron leaf**, then re-executes the forward pass against the registered weights.

What this proves:

> These outputs are the deterministic integer forward pass of the model registered under this `model_id`, on these inputs.

What it does **not** provide:

- **No zero knowledge.** The inputs and outputs are public to the verifier. There is no hiding.
- **No succinctness.** Every node re-executes the whole model. Verification cost scales with the model.
- **No circuit or trusted setup.** There is no SNARK/STARK, no commitment scheme, and no proof compression.
- **No on-chain consumer by default.** The verdict is a stack value. The opcode set has no conditional branch that consumes it, so an application must define what the verdict means for its own state transition.
- **No external input binding.** Inputs are range-checked but not bound to a chain id, height, sender or request id unless the application does that itself.
- **No model allow-list.** The model is caller-chosen and permissionless; soundness is relative to the registered model, not to a governance-approved model.

The Merkle trace is an audit aid: it lets a verifier locate the first divergent neuron instead of only learning that the whole pass failed. It is not a proof of correct inference to a third party who does not re-execute.

::: tip Use the precise wording
If you are integrating zkML, call it **verifiable re-execution with a Merkle trace**. Do not call it a zero-knowledge proof, a succinct proof, or privacy-preserving inference. The code does not support those claims.
:::

## What the native market does not include

- **No external matching engine.** The book is consensus state; there is no off-chain sequencer with a separate truth.
- **No EVM DEX compatibility.** EVM contract execution is not available; the CLOB and PMM are native protocol features.
- **No guarantee of continuous liquidity.** Testnet depth is thin and can change.
- **No audited market invariants.** The matching, PMM curve, session accounting and zkML opcodes are testnet code.

## Next

Move on to [Session keys](/sdk/session-keys) for the client-side grant lifecycle. [Accounts & fees](/core-concepts/accounts-and-fees) explains the balances and gas behind every order.
