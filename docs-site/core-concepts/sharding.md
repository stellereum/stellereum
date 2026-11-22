# Sharding

Stellereum's sharding model is TON-style: one masterchain, workchains beneath it, explicit routing prefixes, and a two-phase commit for value that crosses a shard boundary. The design is implemented and tested. The public network currently runs **shard 0 only**.

## The supported topology

| Shard | Role | Status |
| --- | --- | --- |
| **0** | masterchain: accounts, staking, governance, CLOB, validator set, shard-head commitments, cross-shard hub | **Live** on public testnet |
| **1** | Workchain: workchain accounts, tokens, contracts | **Supported, parked** |

The only supported multi-shard configuration is the fixed pair `{0,1}`, run in **one process per node**:

```sh
STELL_SHARDS=0,1 stellereum run --config node.yaml
```

Do not run one process per shard. The cross-shard transport is node-local: a PREPARE/ACK/COMMIT exchange between two OS processes on the same host, or on different hosts, has no transport. The pair is meant to be run as one node process that owns both shards.

Any shard set other than `{0}` or `{0,1}` is experimental and off. It requires an explicit hatch and is not part of this network.

## Why shard 1 is parked

"Parked" means the code path exists, the tests pass, but the public network does not produce shard-1 blocks. It is not a claim that sharding is live at scale, and it is not a permanent protocol verdict.

Parking is an operational decision:

- A second shard needs the same validator set to run it, with the same genesis and the same faucet funding.
- Cross-shard traffic needs a live soak, not only unit tests. A committed cross-shard transfer has no refund path by design (see below), so a bug is expensive.
- The public testnet has not demonstrated demand that would justify the extra operational surface.

What unparking would require:

1. A coordinated genesis where every node's `node.yaml` lists the same validator set and the same funded faucet account on both shards.
2. Every validator running both shards in one process with `STELL_SHARDS=0,1`.
3. A cross-shard soak that proves exactly-once credit, no duplicate credit on replay, and a source debit of exactly `amount + fee`.
4. Monitoring for shard stalls, state-root divergence at a common height, and cross-shard mailbox growth.

A **split** is a different operation from running `{0,1}`. Splitting grows a routing prefix by one bit and migrates accounts; merging removes the deepest bit. Neither has ever run on a live network. The implementation publishes hard bounds:

| Parameter | Value |
| --- | --- |
| Minimum accounts per shard | 100 |
| Maximum shards (shipped cap) | 16 |
| Maximum prefix bits (advertised space) | 60 |
| Split threshold | 500 (tx load in the block window) |
| Merge threshold | combined load ≤ 50 |
| Shard ids | Never reused |

The advertised prefix space is address space, not capacity.

## Routing rule

One rule decides where an address lives (`workchain-prefix-v1`):

- **Shard 0 is addressed explicitly**, TON-style: `-1:<address>` or `0:<address>`. A bare 32-byte address **never** routes to the masterchain.
- **A bare address is a workchain address.** It routes to the shard whose routing prefix (the top `prefix_len` bits of the first 8 bytes) is the **longest match**.
- Ties break by the **smallest shard id**.
- A split grows the prefix by exactly one bit. A merge removes the deepest bit.
- Shard ids are never reused.

With a single workchain shard (prefix length 0), every workchain address matches it. After a split, addresses with first byte `< 0x80` route to one child and `>= 0x80` to the other.

For ordinary value transfers on the public network, both sender and recipient are on shard 0, so the transaction is same-shard and needs no prefix.

## Cross-shard value: two-phase commit

Cross-shard value uses 2PC, active from genesis (`XPC_ACTIVATION_HEIGHT = 0`). The deprecated `STELL_XPC_ACTIVATION_HEIGHT` variable is ignored; two nodes with different local values would classify the same transfer differently and split the chain.

```text
source shard                                   target shard
────────────                                   ────────────
1. PREPARE
   debit sender
   escrow amount + fee
   publish outbound record  ─────────────────▶ 2. validate
                                                  do NOT credit yet
                                               3. PREPARE-ACK
   ◀─────────────────────────────────────────── acknowledge

4. COMMIT  ──────────────────────────────────▶ 5. credit EXACTLY once
   release escrow                                 duplicate COMMIT = no-op
```

Properties that matter:

- **No credit before COMMIT.** An opening PREPARE cannot create spendable value on the target.
- **Exactly-once credit.** The target records the message id and treats a duplicate COMMIT as a no-op.
- **Committed means committed.** There is no refund path for a committed transfer. If the target is Byzantine, the protocol burns rather than risk a double spend.
- **Source debit is exact.** The sender is debited `amount + fee_charged`; the escrow is released, not refunded.
- **A replay does not re-credit.** Replaying the same raw transaction or COMMIT does not create a second balance.

If a transfer does not complete, the source-side escrow can time out and refund under the 2PC rules. Once COMMIT is observed, that option is gone.

### First-spend caveat for fresh PQ accounts

A fresh post-quantum account has a short trie leaf until its first spend. Its **first** spend must be same-shard: the first spend pins the full PQ account leaf at apply time. A cross-shard first spend is refused at target admission because the proof shape and the target's metadata do not match. Cross-shard transfers work from the **second** spend onward.

If you are onboarding a new account and immediately moving value across shards, fund it and make one same-shard spend first.

## Observing shards

```sh
RPC=https://rpc.stellereum.org

curl -sS "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_getShards","params":[]}'

curl -sS "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_getShardTopology","params":[]}'
```

On the public network, expect the live shard set to be `{0}`. A node that claims a different topology from its peers is misconfigured or on the wrong fork.

## What sharding is not

- It is **not** a live multi-shard network today. Only shard 0 produces public blocks.
- It is **not** a rollup or a sidechain. Shards share one node process and one validator set, with a protocol-level 2PC.
- It is **not** a dynamic auto-scaling system in production. Split and merge code exists with hard caps, but no live split has been performed.
- It is **not** a substitute for auditing. Cross-shard state transitions are consensus code; the testnet has no external audit.

## Next

Continue with [Consensus & finality](/core-concepts/consensus-finality) for shard-head finality, or [Architecture](/get-started/architecture) for the process topology. [Addresses](/get-started/addresses) explains the routing prefixes.
