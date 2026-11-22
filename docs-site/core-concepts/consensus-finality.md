# Consensus & finality

Stellereum uses a Byzantine-fault-tolerant consensus with explicit propose, prevote, precommit and commit phases. Validators are weighted by stake, and a block becomes final as soon as it carries a precommit quorum.

## Validator power

A validator's power is its **self-bond plus delegated stake**. Only self-bond elects: delegations add weight to an existing validator but cannot put a new validator into the set. The entry floor is **1,000 STELL of self-bond**, and a new bond must carry **1,100 STELL** (the 1,000 STELL minimum plus a 100 STELL buffer) so that a single downtime slash cannot push it below the election threshold.

The validator set is refreshed at a height boundary, not mid-round. A set change decided for height `H` takes effect for `H+1`; the quorum threshold in force for a round cannot change under that round.

## Quorum

For total voting power `W`, the quorum is:

```text
quorum = floor(2 · W / 3) + 1
```

This is the smallest integer strictly greater than two thirds of the power. Two quorums must overlap in more than one third of the power, which is what makes conflicting finalized blocks impossible while Byzantine power stays below one third.

### Why 3-of-4 is the live floor

With four equal-power validators, `W = 4`:

```text
floor(2 · 4 / 3) + 1 = floor(2.66…) + 1 = 3
```

So **three signatures out of four** are required. One validator can be offline and the chain still finalizes; two offline and it cannot. The live testnet set is sized so that this is the operative floor, not a theoretical example.

A two- or three-validator set behaves more strictly: with two equal validators the quorum is `floor(4/3)+1 = 2`, i.e. both must sign; with three it is `floor(6/3)+1 = 3`, i.e. all three. Do not assume a single validator can be lost on a small set.

An empty or zero-power set returns an unreachable quorum, never `1`. That fail-closed rule prevents a node from finalizing alone when its validator set is misconfigured.

## Rounds

Each height runs one or more rounds. A round has a scheduled proposer derived from the validator set, the height and the round number.

```text
             ┌──────────┐
             │ PROPOSE  │  scheduled proposer broadcasts a block
             └────┬─────┘
                  │ valid proposal
             ┌────▼─────┐
             │ PREVOTE  │  validators verify and prevote the block hash
             └────┬─────┘
                  │ prevote quorum for the same block
             ┌────▼──────┐
             │ PRECOMMIT │  validators precommit; this is the quorum certificate
             └────┬──────┘
                  │ precommit quorum
             ┌────▼─────┐
             │  COMMIT  │  block is final; effects are applied
             └──────────┘
```

Key properties:

- **Precommit requires a prevote quorum for the same block.** Precommits alone do not decide a block.
- **A locked validator does not prevote a conflicting block.** The lock is what protects safety across rounds.
- **A message advances the round by at most one.** A peer cannot buy a thousand rounds with one packet; rounds move on the node's own timeout.
- **A block is decided only with a precommit certificate** bound to the height, round and block hash, and verified against the validator set the node itself holds.

## View change

If a round does not reach a prevote quorum — a dead proposer, a network partition, a proposal that fails verification — validators time out and advance to the next round. The proposer schedule rotates, and the new proposer builds on the highest locked block rather than inventing a conflicting history.

View change is a liveness mechanism, not a safety reset. A validator that locked on a block in round `r` still refuses to prevote a conflicting block in round `r+1`. Finality already achieved at a lower height is never rolled back.

## Single-block finality

A block that carries a precommit quorum of `floor(2 · W / 3) + 1` is **final**:

- One finalized block is final. There is no probabilistic confirmation window.
- Finalized blocks never roll back.
- "N confirmations" means N finalized blocks on top. Depth is an operational buffer against stale reads, a lagging indexer or a confused client — not a reorg-safety requirement.
- If the network temporarily cannot finalize, it stalls. It does not produce a shorter or conflicting finalized history.

This is why `stell_getTransactionReceipt` reports `confirmations: 1` at the inclusion height with the meaning "already final". A depth of 2–3 is still reasonable for ordinary payments, 10+ for large transfers, and 30+ with a second-node receipt check for custodian crediting. Those are policy choices, not consensus requirements.

## Failure behavior

| Situation | Result |
| --- | --- |
| One validator offline (4-validator set) | Quorum still reachable; chain finalizes |
| Two validators offline (4-validator set) | Quorum unreachable; chain stalls at the last finalized height |
| Conflicting proposals at one height | At most one can gather a precommit quorum; the other is invalidated |
| Validator votes on two conflicting blocks | Equivocation evidence; subject to slashing |
| Node restarts with a stale round | The persisted safety record and the round rules prevent a conflicting decision |

Losing branches that were observed but did not finalize are reported through `stell_getInvalidations` (a rolling window) and the `invalidations` push topic. A consumer that sees an invalidation should re-sync from the reported height rather than assume its previous view was final.

## Staking, jail and exit

- **Unbonding period:** 2 days. Unbonded stake is withdrawable only after the cooldown elapses.
- **Downtime jail:** a validator that misses enough blocks is jailed and excluded from the set. It stays slashable and cannot earn until it is unjailed.
- **Unjail delay:** a jailed validator becomes eligible for `unjail` **4,000 heights** after the jailing penalty, which is deliberately longer than the downtime-penalty cooldown so it cannot immediately re-offend.
- **Unjail authority:** under Ruleset v7 the cold withdrawal key signs the unjail, not the hot voting key.
- **Exits stay open:** jailing does not hold funds hostage. `unbond`, `undelegate` and redelegation remain available.

See [Validator setup](/nodes/validator) for the operator procedure and [Accounts & fees](/core-concepts/accounts-and-fees) for the fee side of staking operations.

## What finality does not mean

Single-block finality is a statement about **consensus safety**: no honest node will finalize a conflicting block at the same height. It is not a statement that:

- the code has been externally audited (it has not);
- an RPC response is fresh (query the node you trust, and check the height);
- an indexer has caught up (indexers lag);
- a bridge or exchange should credit on one confirmation without its own risk controls.

## Next

Read [Sharding](/core-concepts/sharding) next for cross-shard commits, then [Validator setup](/nodes/validator) for the operator side. The [JSON-RPC reference](/api/json-rpc) lists the validator and finality reads.
