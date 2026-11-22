# Contract-originated cross-shard sends: confirmed burn and refusal

Status: safety fix, active from genesis. This document does **not** describe a
working cross-shard contract-message protocol; none exists.

## The confirmed defect

A WASM contract calling `host.send_message` for a recipient whose address→shard
resolution is **not** the executing shard took a separate router branch that:

1. synthesized `Transaction { from, to, amount, nonce: 0, source_shard,
   target_shard, signature: vec![], .. }` — an unsigned transaction that never
   appears in `Block.transactions`;
2. built the record with `source_state_root = [0; 32]`,
   `finalized_in_block = [0; 32]`, no Merkle inclusion proof and
   `source_balance = 0`;
3. **overwrote** the canonical construction `msg_id` with the contract-supplied
   `ContractMessage.msg_id`; and
4. on the hardened path, **debited** `accounts[msg.sender].balance -= value`
   before pushing the record into `cross_shard_out`.

No consumer exists for such a record (only tests call `take_cross_shard_out`),
and the inbound path requires, in order:

- `verify_msg_id()` — the id must equal the canonical
  `(source, target, tx_hash, finalized_in_block)` recompute;
- `tx.verify_signature()` — the carried transaction must be authenticated;
- `verify_cross_shard_escrow_anchored(msg)` — a proof of the **source-side
  escrow/debit leaf**, anchored to locally finalized source finality;
- a `source_balance` that covers `tx.amount`.

The synthesized record satisfies none of them, and no escrow leaf was written
because the synthetic transaction never applied in a source block. Net result:
the value was debited at the source, never delivered at the target, and never
bounced — a **burn**.

## Refusal semantics (active from height 0)

`WASM_XSHARD_CONTRACT_SEND_REFUSAL_HEIGHT = 0` in `src/chain_spec.rs`, with
`wasm_xshard_contract_send_refusal_active_at(height)`.

When the gate is active:

- a contract outbound message whose resolved target shard differs from the
  executing shard is **refused before any mutation**. The whole payload
  reverts with the deterministic error
  `cross-shard contract messages are not available: no authenticated delivery protocol is active`;
  the transaction takes the normal revert/failure-fee path and the sender keeps
  the value;
- `cross_shard_out` stays empty and no account is debited, for both
  value-bearing and zero-value messages (the record itself is invalid, not
  merely the value movement);
- the hardened router is also defensive: if it is ever reached with such a
  message (for example post-commit), it skips the debit and the enqueue;
- **same-shard** contract messages are unchanged: they still route to the
  recipient's actor inbox and bounce exactly as before;
- **inbound** validation is unchanged. The `msg_id` / signature / escrow /
  finality checks must never be weakened — they are what stop a Byzantine
  carrier from minting value.

### Why `0` is safe

The refusal removes no working feature. There is no authenticated producer, no
committed escrow leaf, no delivery consumer and no bounce path for these
records, so every message it blocks was already a guaranteed burn. Activating
at genesis therefore only replaces silent value destruction with a
deterministic revert.

## Prerequisites for a real protocol

A future protocol must supply ALL of the following before this refusal can be
replaced (each needs its own activation gate and consensus review):

1. a **canonical `msg_id`** derived from source, target, transaction hash and
   finalizing block — never taken from contract input;
2. a **committed escrow leaf** in the source state trie for the debited value,
   with a Merkle proof against the source state root;
3. **anchored source finality** the target can verify locally (anchored source
   header / finalized-in-block);
4. an **authenticated carried transaction** (or an equivalent authenticated
   producer identity) so the target knows who authorized the debit;
5. an actual **delivery** path consuming `cross_shard_out` and crediting the
   target exactly once (replay protection);
6. **bounce / two-phase-commit** semantics so an undeliverable message returns
   the escrowed value to the sender exactly once.

Until then, the refusal is the only safety-positive behavior.
