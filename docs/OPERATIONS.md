# Operating a Stellereum node

> 2026-11-04 changelog: removed legacy-genesis env-knob row (§11 env table) — knob is removed/inert, keygen strict-only (see replacement row for citations).

For standing one up, see [`../testnet/README.md`](../testnet/README.md). For
the method list, see [`RPC.md`](RPC.md). For the invariants, see
[`../PROTOCOL.md`](../PROTOCOL.md).

This document covers the things that will page you at 3am.

---

## 1. Retention, and the disk warning

**A node on the default settings grows without bound.** That is the design: the
default is archive mode, because dropping a block body is irreversible and
removes the ability to re-execute that block later for an audit.

### The two modes

Controlled by two environment variables:

| | value | effect |
| --- | --- | --- |
| `STELL_ARCHIVE` | unset, `1`, or anything that is not `0`/`false` | **archive** (default). Every block body is kept forever. |
| `STELL_ARCHIVE` | `0` or `false` (case-insensitive) | **prune**. Bodies older than `height - STELL_KEEP_BLOCKS` are deleted. |
| `STELL_KEEP_BLOCKS` | integer, default `50000` | only consulted in prune mode. |

The flag is inverted, which is its own hazard: `STELL_ARCHIVE=0` means *not*
archive. Write the value out explicitly in every deployment. A reader should not
have to know which way round it is.

**Write it out anyway, even though the default is archive.** An operator who
skims the config and assumes the unset value is "minimal" gets maximum
retention, not minimum.

### What survives pruning

Header records are written for **every** block in **both** modes, at
`put_block` time, regardless of the retention setting. Pruning removes the body
and the `by_height` index entry; the header — height, `prev_hash`, `state_root`,
proposer, timestamp, transaction count, gas used, and the block hash — stays.

So pruning is destructive but not blind: the chain remains walkable and a
verifier can check a retained header against a hash it was handed. What you lose
is the ability to re-execute that block. Switching a node from archive to prune
and back does not restore anything.

A body is only removable if its child is retained (`height + 1 < keep_from`), so
the retained suffix always links back to genesis.

### State and domain snapshots

Snapshots of accounts and of every non-account domain are written **every 100
heights**. In prune mode, snapshots older than `height - 300` are also dropped —
a small ring, because `load_state_into` reads only the newest. In archive mode
they are never pruned, so they accumulate too.

This is a second, usually-forgotten growth path: if you turn on `STELL_ARCHIVE=0`
you get both a bounded block store and a bounded snapshot ring, and if you leave
it on you get neither.

### Pruning is not free and not immediate

A prune pass rides the same 100-height cadence as the snapshot job and removes at
most `PRUNE_BATCH` = 20,000 bodies per pass. The reason is that the background
flusher task is the *only* writer to the store; a prune that scanned the whole
tree inline would stall every other write behind it. The next pass is scheduled
from the next snapshot, not from a completion callback. So convergence is
gradual and a store that is far behind the boundary keeps growing for a while
after you enable pruning.

### Sizing

The `./data/store` directory in this repository measured **2.9 GB** after a
period of local running on the default settings. Budget against that. It is not
a per-block constant — it scales with how many transactions each block carries,
and with the snapshot ring — but it is a real number produced by the current
defaults rather than an estimate.

Rough scale on defaults: `STELL_MIN_BLOCK_MS=400` caps a node at ~2.5 blocks per
second, so ~216,000 blocks a day, indefinitely.

#### Minimum hardware (honest floor, not marketing)

| role | vCPU | RAM | disk | IOPS / notes |
| --- | --- | --- | --- | --- |
| **validator** | **≥ 4 vCPU** | **≥ 8 GB** (unit capped at `MemoryMax=2G` for the node process alone; the host needs headroom for sled flush, snapshots and the snapshot-sync replay) | **≥ 100 GB SSD**, < 80 % used | sustained random-write for the sled store + snapshot ring; spinning disk stalls the persist queue (§1 "persist queue") and reads as consensus lag |
| **observer / follower** | **≥ 2 vCPU** | **≥ 4 GB** | **≥ 60 GB SSD** | same SSD requirement; follows the tip, never proposes, but replays every block it adopts |

Reference host everything was measured on: **6-core AMD Ryzen 5 3600,
16 GB RAM** (`docs/PERF_1K.md` §1 — "Reference host"). Live testnet hosts
(`stellereum/docs/handoff/STELLEREUM_SESSION_MEMORY.md:112`) were
**1 vCPU / 3.8 GB RAM** — and that is exactly where the incidents came
from.

**1 vCPU is EXPLICITLY insufficient for a validator.** Measured live on the
1-vCPU stand (`STELLEREUM_SESSION_MEMORY.md:1634`):

- scheduler starvation: probe bimodal (252 < 1 ms vs 240 ≥ 1 ms),
  **> 63 % sys / 36 % iowait, load ~4**;
- transport round-trip 0.35–2 s dominated the consensus loop (median
  broadcast 770 ms, p90 1.5–1.9 s, 48 timeouts / 5.7 min);
- with `STELL_SHARDS=0,1` on one process, **four consensus loops on 1 vCPU
  cost ~25 % of throughput** (173 → 130 TPS, `10.50`), and a second shard
  consensus on the same core starves masterchain votes — the workchain
  falls behind while the masterchain waits on it;
- verdict recorded in-tree: *"1vCPU не потянет два консенсуса"* ("1 vCPU
  will not carry two consensuses", `10.48` discussion) and
  *"Шардинг live — NO-GO … 1vCPU не потянет"* (`10.48` resolutions).

The same code on the 6-core reference host does 571–792 TPS without a
single consensus change (`10.54`: R5 3600 vs 1 vCPU = **×5–6**). The
bottleneck is iron, not architecture — so buy iron before tuning knobs.

#### Disk and inode guidance (the incident that wrote this section)

Live incident (§15, incident 1): one node accumulated **463 589 orphan
chunk files**, consumed all **655 360 inodes (`df -i` = 100 %)**, went
read-only and **silently dropped out of consensus** — while answering RPC
normally. A sibling node with the prune cron never saw it.

Rules:

- Run the sweeper on **every** node, as a timer, not as a one-off:
  `scripts/node-prune-cron.sh --dir <node-dir>` (+ `--dry-run` first),
  systemd units `scripts/systemd/stell-node-prune.service` /
  `stell-node-prune.timer` (§15.4–§15.6). A single node without the timer
  is a single point of failure.
- Alert thresholds: warn at **≥ 80 % inode use**, critical at **≥ 90 %**
  (the `preflight` gate and the join script's disk-guard cron use
  warn 80 / crit 90; §10, §15.3). The number that matters is inodes, not
  bytes:
  ```sh
  df -i ./data          # alert warn ≥ 80 %, crit ≥ 90 %
  df -h ./data          # bytes are the second signal, not the first
  ```
- Retention knobs bound the growth: `STELL_ARCHIVE=0` +
  `STELL_KEEP_BLOCKS=1000000` (§1 "The two modes"). Keep them identical on
  every node.

Pruning is the answer if the disk is finite. A starting point for a public
testnet that must keep a few weeks of re-executable history:

```sh
STELL_ARCHIVE=0
STELL_KEEP_BLOCKS=1000000
```

Set the same values on every node. They are node-local policy and not part of
the state root, so a mismatch does not split the chain — but a node that prunes
aggressively while an operator is auditing an incident on it is a bad day.

### There is no disk metric

`Storage::stored_block_entries()` exists and answers "is the store growing
without bound", but it is called from tests only: it is not exposed over RPC and
not in `/metrics`. `sled 0.34` has no per-tree `size_on_disk`, so it counts keys
rather than bytes. Disk monitoring has to be external:

```sh
du -sh ./data/store
```

Alert on growth rate, not on a threshold. In archive mode the correct alert is
"growing at all, faster than your disk".

### One more write path: the persist queue

Finalized blocks, finalized head, consensus checkpoints and snapshots go through
a bounded background queue of `PERSIST_QUEUE_CAP` = 8192 jobs. It never blocks
consensus. If the disk cannot keep up, jobs are **dropped** and you get:

```
[storage] persist queue full; dropping a job (disk too slow?)
```

That line means state on disk is behind memory. It is logged on `stderr`, not
through `tracing`, so a deployment that only ships the structured log will miss
it. The same applies to `[storage] persist error: …` and to `[rpc] server
error: …`. Watch `stderr` explicitly.

---

## 2. Metrics that matter

There are two Prometheus endpoints and they measure different things.

### The chain: gateway `/metrics` on `STELL_EXPLORER_LISTEN`

The scrape is the consensus [`Registry`](..//src/metrics.rs) (round, height,
vote counters, fork counter, block/tx histograms, latency) plus five
gateway-local gauges appended in the same exposition format
(`src/explorer.rs:808-839`):

```
stellereum_block_height
stellereum_mempool_size
stellereum_contracts_total
stellereum_tokens_total
stell_ready
```

`stell_consensus_height` (registry) and `stellereum_block_height` (gateway)
carry the same height; `stell_mempool_size` appears in both places as well.
See §8 for a full scrape example with `curl`.

**`stellereum_block_height` is the only liveness signal, and you have to derive
the rate yourself.** A gauge alone tells you nothing: a node frozen at height
4,000 and a node producing 2.5 blocks a second both report a plausible number.
Alert on the *derivative* over a window of a few minutes.

What the rate should be: bounded by `1 / STELL_MIN_BLOCK_MS` per node, and by
how often the proposer is scheduled. At the default 400 ms, ~2.5/s. A rate
comfortably above zero but far below the ceiling usually means the proposer is
not being selected on every height.

**`stellereum_mempool_size` is the honest number.** The RPC and the proposer
share one `Mempool` by reference, so this is not a per-layer fiction. It has
three diagnostic readings, listed in [`RPC.md` §7](RPC.md#7-mempool).

### The state: RPC, polled

Neither the rate nor agreement is in `/metrics`. Poll these:

- `stell_getStateRoot` on every node, every minute. **All nodes must return the
  same 64-char hex.** This is the single most valuable check you can run: it
  catches a split chain, a divergent state application, and a node that is
  running alone on its own genesis.
- `stell_getValidators` on every node. Compare `validators`, `total_power` and
  `quorum`. A node that has silently dropped a peer will report a smaller set
  and, if it is also using a different config, a different state root.
- `stell_blockNumber` alongside the root, so you can tell "same chain, different
  height" (normal, catching up) from "same height, different root" (split).

`stell_syncing` is now truthful (true while a recent verified peer sighting
is above our height; sightings expire after 5 min). See §4.

### The network: infnode `metrics-listen` in the YAML

Separate port, separate process-level data, and it only exists if you set
`metrics-listen:` in the node config:

```
infnode_connections_active        # currently active peer connections
infnode_reconnects_total          # reconnect attempts — climbs steadily if a peer is down
infnode_messages_published_total  # pubsub publishes
infnode_messages_delivered_total  # pubsub deliveries
infnode_frames_in_total / _out_total
infnode_bytes_in_total / _out_total
infnode_outbox_size               # pending outbox messages
infnode_outbox_dropped_total
infnode_peers_configured
infnode_uptime_seconds
```

`infnode_connections_active` below your configured peer count, together with a
climbing `infnode_reconnects_total`, is the earliest signal that a validator is
unreachable — long before the height stops. The reconnect loop retries every
20 seconds, so allow one interval before concluding anything.

The pubsub counters are how consensus failure actually presents. `published`
climbing with `delivered` flat means votes are leaving this node and arriving
nowhere, which is exactly the condition under which a 2-validator network
stalls. Deliveries are best-effort by design; the consensus loop re-broadcasts
each round's votes on every view change precisely because a single lost message
would otherwise leave the peer one signature short forever.

### Disk

External. `du -sh ./data/store`, and the alert is on rate of change.

---

## 3. The node refuses to start

### Symptom

```
genesis state root mismatch for this data directory:
  stored: <64 hex>
  config: <64 hex>
This node was previously run with different genesis parameters (validator set,
balances, or STELL_FAUCET_KEY). Continuing would put it on a different chain.
Wipe ./data to start a new chain, or restore the original configuration.
```

The node exits with a non-zero status.

### What it means

At startup the node recomputes the genesis state root from its current config
and environment, then compares it with the one persisted in the store's `meta`
tree under `genesis_state_root`. A mismatch is a hard `bail!`, not a warning.
The root is a function of:

- **the validator set** — which is `{self} ∪ {peers listed in validators:}`; a
  different set means a different set of funded accounts
- **`STELL_FAUCET_KEY`** — the derived faucet account is credited
  1,000,000 STELL at genesis, so a different key is a different account
- **the binary's genesis constants** — `GENESIS_VALIDATOR_BALANCE`
  (100,000,000 STELL), `GENESIS_FAUCET_BALANCE`, the genesis bond
  (1000 STELL), and `COMMITMENT_VERSION` in the state digest. Rebuilding from a
  different revision with different values is a mismatch.

This guard exists because the failure it prevents is silent and bad: the node
used to restore the old state, discard the freshly computed genesis, and carry
on on a chain its own config no longer described — with no error anywhere.

### Triage, in order

1. **Read the two roots.** They are printed. If they differ in one or two hex
   characters you are looking at one extra or one missing account; if they share
   no prefix at all, expect a different set or a rebuilt binary.
2. **Diff the `validators:` lists** between the config that ran before and the
   one running now. This is the most common cause by a wide margin, and it is
   the most common one to be *invisible*: a node that forgets a peer in its YAML
   runs solo without complaining, and the damage only shows up on the next
   restart.
3. **Diff `STELL_FAUCET_KEY`.** Compare with `sha256sum` of the value, not by
   eye, and check it is actually exported — `set -a` before sourcing, or the
   variable is invisible to the process and the node silently skips the credit.
4. **Check the binary.** If the node was upgraded between runs, compare the
   genesis constants in `src/main.rs` and `commitment.rs` against the revision
   that created the data directory.
5. **Check the working directory.** `./data` and `./keys` are relative to the
   current directory. Starting the node from a different directory gives it an
   empty store, which reports no stored root and starts happily on a *new*
   chain — the opposite failure, and the more dangerous one, because nothing
   errors.

### What to actually do

- **The chain is disposable (testnet, no state you care about):** wipe it and
  start over. `rm -rf ./data` — keep `./keys` if you want the same validator
  identity, delete it too if you want fresh keys. Then make sure every other
  node is wiped at the same moment, or you will have a chain where some nodes
  are on the old genesis and some on the new one.
- **The chain has history you care about:** the config is wrong, not the data.
  Restore the original `validators:` list and `STELL_FAUCET_KEY`. There is no
  override flag, by design.

### The case the guard does *not* catch

The guard compares against what that data directory was created with. A node
that has never run has nothing to compare against, so it will start on a
mismatched chain without complaint. This is why the bootstrap procedure in
[`../testnet/README.md` §5](../testnet/README.md) requires a first start, a wipe
of `./data`, and a second start: the wipe is what converts "invisible wrong
genesis" into "verifiable genesis". A cluster can sit in a split state
indefinitely without any node ever complaining, as long as none of them is
restarted against a changed config.

---

## 4. Stalled, or syncing?

**`stell_syncing` answers this** (true = a verified peer is ahead of us within
the last 5 minutes). It is vantage-local: a fully partitioned node reports
false. Combine with height-vs-peers checks below before paging.

### Syncing: what it looks like

Block sync happens once, at the start of the consensus loop, and is best-effort:

- The node reads the peer's published head from `stell:height:<shard>` in the
  P2P KV. If the peer is ahead, it fetches up to 200,000 blocks, validates the
  chain against its own validator set and its own finalized tip, and replays it.
- On success it logs **`[sync] caught up N blocks to height M`** and jumps
  straight to height M+1. There is no incremental background sync: after the
  catch-up completes, the node participates in consensus from the current height.
- `stell_blockNumber` **jumps**, rather than climbing. During the replay itself
  the height does not move.
- State roots agree with the peers once it lands.

If the replay is rejected, you get one line and the node continues from its own
height:

```
[sync] rejecting peer chain: block N: parent state root mismatch (header X, our state Y)
[sync] rejecting peer chain: <validate_sync_chain error>
[sync] validator set has no power; refusing to sync a peer chain
```

The third one means the local validator set is empty or zero-power — in that
case the node **returns from the sync path and never joins the consensus loop
at all**. No height, no RPC progress, no error beyond that line. Check
`stell_getValidators` and its `quorum` field first when a node is completely
inert.

### Stalled: what it looks like

- `stell_blockNumber` flat.
- In the log, a repeating **`[consensus] view change -> height N round R`**
  every 3 seconds. That is the round timeout firing over and over: propose,
  prevote, precommit, no quorum, next round, propose again. The chain is not
  hung, it is failing to decide.
- `infnode_messages_published_total` climbing with
  `infnode_messages_delivered_total` flat, if you have that endpoint.
- `stell_mempoolSize` non-zero and static: transactions are waiting for a block
  that is not coming.

### Diagnosing it

1. `stell_getValidators` on the stalled node, and on a healthy peer if you have
   one. Different sets → the genesis/validator-list problem, go to §3.
2. Compare `quorum` against `validators.length()`. If they are equal, **every**
   validator must sign and any one absence halts the chain. See §5.
3. `stell_getBalance` on a known validator address, on the stalled node and on a
   healthy one. Different balances → different genesis, go to §3.
4. `stell_syncing`: true = behind but hearing peers; false + stalled height = genuinely stuck (or partitioned — check peers).
5. If the height is moving but the state root is not changing, you are producing
   empty blocks — that is normal on a quiet testnet, and it means you should be
   worried about disk instead (§1).

### The other silent-stall case

A proposal that is rejected logs a line and is otherwise indistinguishable from
a peer that is not proposing:

```
[consensus] RX proposal from <peer> #N rR
[consensus] rejected proposal from <peer> at #N rR: <reason>
```

Rejections are logged at info and are never swallowed. If you see a proposal
rejected and then nothing, look for what comes after it. This line is the
difference between liveness and a silent stall.

---

## 5. Taking a validator offline

### With two validators, one node down stops the chain

`quorum_power()` is `floor(2 × total_power / 3) + 1`. With the genesis bond of
1000 STELL every validator has power 1, so:

| validators | total power | quorum | can one node be down? |
| --- | --- | --- | --- |
| 1 | 1 | 1 | n/a (solo testnet) |
| 2 | 2 | **2** | **no** |
| 3 | 3 | **3** | **no** |
| 4 | 4 | 3 | yes |
| 5 | 5 | 4 | yes |

Two things to internalise:

**With two validators, quorum is two, so both must precommit every block.** Not
"one of two". The 2/3 formula rounds *up*, and at n=2 and n=3 it demands
everyone. If you assumed a 2-validator testnet would tolerate one outage, it does
not, and three validators is no better than two.

**Killing a node does not let the survivor continue.** This is the operational
trap. The survivor has power 1 against a quorum of 2. It cannot reach a precommit
quorum, so it cannot finalize. It does not fall back to solo finalization, and
there is no such mode:

- Block sync is gated on quorum too. `quorum_power()` returns `u64::MAX` for an
  empty or zero-power set so it **fails closed** — but the more common case here
  is not an empty set, it is a set of 2 with only 1 reachable, and a certificate
  from a single node is rejected against that set.
- A peer cannot make the survivor finalize anything it did not genuinely
  finalize: `adopt_committed` verifies the certificate against the **local**
  validator set, so a single node's commit is refused.
- The genesis fingerprint guard blocks the other move: giving the survivor a
  fresh data directory would recompute a *solo* genesis root, which either
  refuses to start or — on an empty directory, where there is nothing to compare
  against — starts a second, private chain while the rest of the network
  continues on the first.

What the survivor actually does is spin: re-propose, re-broadcast its votes every
3 seconds on each view change, and never advance. That is by design — a chain
that finalizes blocks with no real quorum is worse than a chain that stops.

**The fix is more validators, not a flag.** Four validators give a quorum of 3,
and the chain then survives one node being offline. Going to three does not help
at all. Adding a validator is a config change on every node (`validators:` list
plus a `peers:` entry) and a restart, so plan for it before you need it — you
cannot add a validator to a halted 2-validator network, because the halted
network has nothing to halt *into*.

### The economic consequence of downtime

Driven entirely by block evidence, never by local observation (PROTOCOL.md I5). A
local "I haven't heard from you" timer would slash honest peers that were merely
partitioned, and two nodes would reach different verdicts. Instead: a validator
that did not sign the **precommit certificate of a finalized block** counts as
missed, derived from that block, so every node counts identically.

| | |
| --- | --- |
| consecutive missed heights before a penalty | **10** (`DOWNTIME_MISS_THRESHOLD`) |
| penalty | **0.1%** of the validator's total stake (`DOWNTIME_SLASH_BPS` = 10 bps), self-bond first, then delegated |
| cooldown between penalties | **100 heights** (`DOWNTIME_PENALTY_COOLDOWN`) |
| forgiveness | signing again resets the missed counter to 0 |
| equivocation (double-vote) | **5%** (`EQUIVOCATION_SLASH_BPS` = 500 bps), no cooldown |

The burn is real: the amount is debited from the staking pool account, not
recorded in a counter, so total supply and the pool balance cannot drift from the
sum of individual slashes. A genesis validator bonded at 1000 STELL loses
1 STELL per downtime penalty and 50 STELL per equivocation.

The cooldown deliberately does **not** apply to a first offence, because on a
chain younger than 100 heights nobody would ever be punished.

**Scale this to your block time.** `STELL_MIN_BLOCK_MS` defaults to 400 ms, so on
a default-paced network 10 consecutive misses is about **4 seconds** and the
100-height cooldown is about **40 seconds**. If you are running a busy testnet
with a validator on a shared host, a 5-second GC pause or a container restart is
enough to burn. If you want a realistic window, raise `STELL_MIN_BLOCK_MS`.

And the counter-intuitive part: **a 2-validator network that has halted cannot
slash you at all.** Slashing needs a finalized block, and a finalized block
needs quorum, and quorum needs both validators. The chain stopping is the
punishment. Once you are at four validators and blocks keep flowing, the downtime
accounting starts.

### Practical guidance

- **Run four validators, not two.** It is the smallest size where losing one node
  is survivable.
- **Drain, do not kill, for planned work.** Stopping a node in a quorum-required
  set stops the chain regardless of how gracefully you stop it. There is no
  "leaving the validator set" mechanism in this code — the set is re-derived
  from the staking ledger, and unbonding takes an unbonding period
  (`UNBONDING_PERIOD_SECS`, 2 days at the 3s block rate the constant's comment
  assumes, which is not the 400 ms default — at 400 ms it is 2 days of blocks,
  which is the same wall-clock time but 5× more of them).
- **Ctrl-C, not `kill -9`.** The node persists finalized blocks, the finalized
  head, and a consensus safety checkpoint, and restores the lock on restart so it
  cannot double-vote a height it already locked. An unclean stop loses at most
  the blocks since the last background flush and does not break safety, but it
  does mean a resync.
- **Watch `missed` indirectly.** There is no RPC for a validator's `missed`
  counter or `last_downtime_penalty`. The closest observable is
  `stell_stakeOf`: a validator whose `total` is below the 1000 STELL genesis
  bond has been slashed. Compare it across nodes to catch a divergent ledger
  early — `total_slashed` is part of the state commitment, so disagreement there
  means the state roots disagree and you have a split.

---

## 6. Exposure checklist

Before anything is public:

- `STELL_RPC_LISTEN` and `STELL_EXPLORER_LISTEN` default to `127.0.0.1`. Setting
  them to `0.0.0.0` publishes the node. The RPC port is **not** rate limited —
  the limiter is a gateway-layer middleware and the raw JSON-RPC router has none.
- `STELL_RPC_AUTH_TOKEN` gates `stell_sendRawTransaction` and nothing else.
- `STELL_FAUCET_TOKEN` gates `stell_faucet`, and is **fail-closed**: the faucet
  is only ever open if you set this. With `STELL_FAUCET=1` and no
  `STELL_FAUCET_TOKEN`, the node starts but every `stell_faucet` call is
  refused with `refusing to dispense`. Do not rely on the general write token
  for this — the faucet deliberately takes its own, so a public testnet can
  serve reads while still rationing who draws from the treasury.
- Two more things to fix before exposing a faucet at all: set a **random**
  `STELL_FAUCET_KEY` (the test seed is the literal constant `0x11..11`, which is
  public in this repository), and remember the faucet's nonce and per-address
  `dispensed` totals are persisted under `faucet_state_v1` and loaded at startup
  (`src/rpc.rs`), so they survive a clean restart; an unsynced node can still
  diverge from the chain because they are not consensus state.
- `allow-unknown: true` in the node config accepts connections from nodes that
  are not pinned. The default `unknown-allow` list grants four read-only DHT
  discovery capabilities and nothing else, but spell it out rather than relying
  on the default.
- The gateway sends `access-control-allow-origin: *` on every response and
  nests the JSON-RPC router at `/rpc`. Rate limiting is per IP and in-process: a
  speed bump, not access control.
- `metrics-listen` in the YAML exposes transport counters. Keep it on loopback.
- `chain_id` is hardcoded to 5757 and there is no way to change it, so it cannot
  be used to separate a testnet from a mainnet deployment of the same binary.
  Separate them at the network level.
- The faucet key is an ordinary ed25519 seed with no encryption requirement in
  this code. It is in your shell environment, potentially in your process table,
  and it controls a real genesis balance. Keep it out of shell history, out of
  CI logs, and out of the repository.

---

## 7. Live incident lessons

Distilled from a long live-debug session. Each item burned hours once; record
so it is not rediscovered.

### 7.1 One-directional transport blackouts

Symptom: consensus checks green, `view change` every 3s (§4), chain stalled
~10 min. Requests to the peer return ok but nothing arrives, or hang.

- `broadcast` logs every outcome, never swallows (`src/consensus_net.rs:199`):
  `ok` (debug), `denied/fast-fail` on `{"ok":false` (`:222`), `transport-err`
  (`:237`), `TIMEOUT after ~2s` (`:247`).
- `TIMEOUT-after-2s` with no receiver-side `req` lines = dead cached
  connection. The 2s budget preempts the inner 120s self-heal, so the dead
  conn is reused forever unless evicted (`:233-252` calls
  `invalidate_peer_conn`).
- Fast `ok:false` denial plus receiver `req_denied` lines = ACL/config
  problem, not transport (`:193-198`).
- `probe_peers` (`:157-186`) runs every ~30s (`src/main.rs:1123-1128`):
  `core.ping` per peer, `[net] probe <id> ok/err/TIMEOUT`; TIMEOUT evicts the
  conn (`:178-182`). A failing probe names the dead direction in one line.
- `join` re-registers the topic subscription every 5s until peers connect
  (`src/main.rs:1111-1116`, `src/consensus_net.rs:140-151`).
- Recovery to date: clean restart, every time (§7.2). Eviction narrows the
  window; it does not replace the restart.

### 7.2 Restart procedure

Use the script. Never hand-roll `nohup` without the env files: `start_one`
sources `$ENV_A`/`$ENV_B` with `set -a` and launches
`run --config node.yaml --shard 1` via `setsid nohup`
(`scripts/stell-node.sh:60-62`). A manual launch without env silently changes
genesis (§3), ports, and tokens.

- `stell-node.sh restart` = `stop_all` then `start`
  (`scripts/stell-node.sh:354`). `stop_all` (`:65-90`): SIGTERM, poll to zero
  (up to 30s for the ~15-20s drain/flush + sled lock release), then
  SIGKILL+5s, then FAIL rather than start duplicates.
- Manual equivalent: kill, sleep 20+, verify zero procs
  (`pgrep -f "$BIN run"` must be empty), then start. Starting early fails
  with `could not acquire lock on ./data/store/db` (WouldBlock) (`:70-73`).
- `start` refuses when old processes linger (exit 2)
  (`scripts/stell-node.sh:238-254`); `start --force` is stop-first.
- Binary replace: never `cp` over a running binary (ETXTBSY risk, `:70-73`).
  Use `deploy <path>`: `cp src BIN.new && mv BIN.new BIN`
  (`scripts/stell-node.sh:374-380`).
- Watchdog (`scripts/stall_watchdog.sh`): polls both RPCs every 30s
  (`POLL_SECS`, `:14`); if neither height advances for `STALL_SECS=180`
  (`:15`), delegates to `stell-node.sh restart` (`:46-51`). Never wipes data
  (`:9`); process crashes (< 2 procs) are operator-owned, not restarted
  (`:34-38`).

### 7.3 Poison snapshots (label = engine height, never tip)

A snapshot labeled F whose bytes are really state-S poisons the store: the
next restart loads "state at F", skips healing (S == F), and votes from stale
state while reporting healthy. Observed live twice (label 367 / content ~290,
`src/storage.rs:606-609`; 201-state labeled 273/274, `src/main.rs:708-714`).

- Rule (`src/main.rs:704-731`): on startup, if the finalized tip has no
  snapshot at/above `restored_state_height`, snapshot the engine **at
  `restored_state_height`**, never at the tip `fh`. Log line:
  `wrote a snapshot of engine state at height S (tip F)` (`:729`).
- Restore is verified before install: throwaway restore + `verify_restored_root`
  (`src/storage.rs:606-621`, `:443-478`). No anchor and snapshot < tip =
  refuse (`:460-464`); anchor mismatch = refuse (`:469-476`).
- Wipe = last resort, and for a fork both nodes simultaneously
  (`stell-node.sh wipe/clean`, `scripts/stell-node.sh:355-366`; same warning
  as §3). Wiping one node of a forked pair just re-forks it.

### 7.4 Faucet nonce gaps after mempool wipes

The mempool never survives a restart, so drips reserved (nonce advanced +
persisted) but never included leave a permanent gap: on-chain nonce never
meets the reservation, new drips wait behind phantom predecessors forever.
Observed live: faucet nonce 20+, on-chain 0, every drip stuck
(`src/main.rs:2191-2208`).

- Startup: faucet state (nonce + per-address caps) is loaded from
  `faucet_state_v1`, then `clamp_nonce_down(onchain)` — down only, never up
  (`src/main.rs:2184-2208`; `src/rpc.rs:143-149`).
- Steady state: `build_transfer` takes `reconcile = (on-chain, pending)` and
  assigns mex(on-chain, pending) — smallest nonce neither executed nor pending
  (`src/rpc.rs:178-194`). `None` keeps pure increment (tests/single-shot).
- Mempool is saved every 15s + on SIGTERM/Ctrl-C to bound the loss window
  below the watchdog threshold (`src/main.rs:1130-1142`, `:2213-2239`).

### 7.5 TPS harness (`scripts/tps_load.py`)

- `--shard 1` is mandatory: must match the node's `--shard`
  (`tps_load.py:898-899`; node launches with `--shard 1`,
  `stell-node.sh:61`).
- `--gas` must be above the base fee: mempool rejects
  `tx.gas_limit < base_fee` (`src/mempool.rs:219`); the floor is
  `STELL_MIN_GAS_LIMIT`, default `GAS_BASIC_TRANSFER`
  (`src/main.rs:2120-2128`).
- Funding: `--faucet-token` (default path, `tps_load.py:886`) vs
  `--direct-fund-key` (64-hex seed, locally-signed transfers, robust when the
  faucet nonce gaps; fetches on-chain nonce, assigns contiguous nonces,
  `:888-892`). Resume ignores funding flags (`:721-722`).
- Resume mode: `--keys-file <path> --resume --run` (`:909-918`). Loads the
  SAME keys, queries CURRENT nonce per account via `stell_getBalance`, blasts
  only the remainder with contiguous nonces (200/acct/wave cap); prints
  `resumed-from/total` per account (`:735-771`). `--resume` without
  `--keys-file`, or a missing keys file, is a hard error (`:713-719`).

### 7.6 Status script fields (finalize vs adopt aware)

A node that missed the deciding vote advances by ADOPTING
(`adopted committed block #H`, `src/main.rs:1330`) without ever printing
`FINALIZED block #H (state root ...)` (`:1378`). Status must treat either as
progress (`scripts/stell-node.sh:112-149`).

- Per node: `last_finalized` (`:104-110`), `last_adopted` (`:116-121`),
  `max_height` = max of the two (`:130-138`), `tip_hash` behind it
  (`:141-149`), `viewchange` = height TRYING to advance at (`:124-128`).
- `status` prints `processes`, `last_finalized`, `finalizes A/B`,
  `last_adopted`, `adopts A/B`, `max_height A/B`, `viewchange A/B`
  (`:172-230`); `status4` same across A-D (`:282-332`).
- Verdicts: HEALTHY on equal finalized height+root, else HEALTHY on equal
  max height with no conflicting root/tip (`:216-224`); STALE CHAIN on
  `lacks a validator quorum` (`:210-214`); NOT RUNNING / NOT SYNCED
  otherwise. `wait` requires two DIFFERENT height samples — equal samples
  prove nothing (`:151-170`).

---

## 8. Backup & restore

Full reference: [`../scripts/backup/BACKUP.md`](../scripts/backup/BACKUP.md).
Scripts: `scripts/backup/backup.sh`, `scripts/backup/restore.sh`. Both are
rooted at `${STELL_ROOT:-/root}`, so every command below is dry-runnable
off-host with `STELL_ROOT=/tmp/fake-stand` (verified: `bash -n` on both
scripts, `--help` / bad-arg exits 2, backup+restore round-trip over a fake
stand, wrong-node restore refused with exit 1).

### What is backed up

One tarball per node (`stell-node<A|B>-<UTC-timestamp>.tar.gz`, mode 600 —
treat as secrets, never commit), members relative to `$STELL_ROOT`
(`tar -p` preserves modes):

| tarball member | live path | why it matters |
| --- | --- | --- |
| `nodeA/node.yaml` | `/root/nodeA/node.yaml` | peer set, listen/advertise addrs — defines the chain |
| `nodeA/data/` | `/root/nodeA/data/` | everything below, including the store |
| `nodeA/keys/` | `/root/nodeA/keys/` | `identity.key`, `e2e.key` (dir 700, files 600) |
| `env.A` | `/root/env.A` | `STELL_RPC_LISTEN`, auth/faucet tokens (mode 600) |

(Same with `B` for node B.) Inside `data/` the load-bearing entries are:

| path | contents |
| --- | --- |
| `data/store/` | sled store (`store/db` + snapshots) — the chain itself |
| `data/kv.json` | node-local DHT KV (head pointers, mempool/shard indices, prune cursor) |
| `data/mail.key` | node transport identity (stable peer id across restarts) |
| `data/mempool.bin` | mempool spill file (best-effort, rebuilt live) |

### NEVER delete to "fix" anything

- Never delete `data/store`, `data/kv.json`, or `data/mail.key` individually
  — not to free disk (§1/RUNBOOK disk section: free the journal and stale
  `*.log` instead), not to clear a faucet nonce gap (§7.4), and not to clear
  a `genesis state root mismatch` (§3). A single deleted file is a torn
  identity: the node either refuses to start or starts a private chain.
- A wipe is **whole `./data` on every node at the same moment**
  (`stell-node.sh wipe`/`clean` deletes both data dirs; `restore.sh` extracts
  whole `data/` over `$ROOT`). Mixed old/new data dirs never agree.
- `restore.sh` refuses to restore over a live node (systemd stop + `/proc`
  cwd scan, exit 1) and never `kill -9`s to force it. It snapshots the
  current state to `pre-restore-node<A|B>-<ts>.tar.gz` first, so a bad
  restore is reversible.

### Backing up (exact)

```sh
# trustworthy backup: stop first (a hot tarball can catch sled mid-write),
# then back up, then start again
systemctl stop stell-nodeA   # resp. stell-nodeB
scripts/backup/backup.sh --node A
systemctl start stell-nodeA

# both nodes, defaults (--keep 7 each, --dir $BACKUP_DIR or /root/backups)
scripts/backup/backup.sh
# one node, custom destination/retention
scripts/backup/backup.sh --node A --dir /root/backups --keep 14
```

Each tarball is verified immediately (`tar -tzf` lists, all four members
present) before retention pruning keeps only the N newest per node.

### Restoring (exact)

```sh
# 1. restore.sh stops the unit itself, then checks /proc for stragglers.
#    If it refuses, STOP here and investigate — do not force it.
scripts/backup/restore.sh /root/backups/stell-nodeA-20260926T120000Z.tar.gz A

# 2. sanity-check what landed (optional but recommended)
tar -tzf /root/backups/stell-nodeA-20260926T120000Z.tar.gz | head
diff <(tar -xzOf /root/backups/stell-nodeA-20260926T120000Z.tar.gz nodeA/node.yaml) /root/nodeA/node.yaml

# 3. start by hand (restore.sh deliberately does NOT start the node)
systemctl start stell-nodeA && journalctl -u stell-nodeA -f
```

If the node then exits with `genesis state root mismatch`, the backup
predates a genesis change (validator set, balances, `STELL_FAUCET_KEY`) —
that refusal is the safety net, not a bug. Restore a backup taken after
the change, or wipe every node's `./data` for a new chain (see §3 and
`BACKUP.md` § "Fingerprint mismatch").

### Read-only health check

`scripts/health_check.sh` is the read-only complement to
`scripts/monitor/check.sh`: two `stell_blockNumber` samples (`--interval`,
default 6s) per `--rpc` port, one `stell_mempoolSize` sample per port
(degraded at `--crit`, default 9000 of the 10000 cap), `df` on `--disk`
(warn `--warn` 85 / crit `--crit` 95), and a read-only REFUSING-pattern scan
(`journalctl -u stell-nodeA/B`, falling back to
`$STELL_ROOT/nodeA|B/current.log`) for `genesis state root mismatch`,
`lacks a validator quorum`, `refusing to dispense|finalize|adopt`,
`admission refused`, `FINALIZE-BLOCKED`, `rejected proposal`. Exits
0 healthy / 1 degraded / 2 down-or-bad-usage; writes nothing.

```sh
scripts/health_check.sh
scripts/health_check.sh --interval 10 --rpc "8545" --disk / --warn 85 --crit 95
```

---

## 9. Explorer probes with example outputs

Gateway base: `STELL_EXPLORER_LISTEN` (default `127.0.0.1:8080`). All three
are `GET`, all behind the same per-IP limiter + CORS as the rest of the
gateway (`src/explorer.rs:860-902`). Legacy binaries (deployed pre-readiness)
answer 404 on `/healthz` and `/readyz` and export no `stell_ready` gauge —
any HTTP answer still means "process alive"; `scripts/monitor/check.sh`
handles both cases.

### `GET /healthz` → 200 (liveness, cheap by design)

No locks, no state reads, so a wedged subsystem cannot fail it
(`src/explorer.rs:745-750`). Use `/readyz` to ask whether the node is
actually useful.

```sh
curl -s http://127.0.0.1:8080/healthz
```

```json
{"status":"ok","service":"stellereum-gateway"}
```

### `GET /readyz` → 200 or 503 (readiness, names the reason)

200 when the node finalized recently, holds peers, and its height advances;
503 with the same shape and a non-empty `failed_checks`
(`src/explorer.rs:752-771`). Thresholds: `STELL_READY_MAX_STALL_SECS`
(default 30), `STELL_READY_MIN_PEERS` (default 1, `0` for solo/dev).

```sh
curl -s -w '\nHTTP:%{http_code}\n' http://127.0.0.1:8080/readyz
```

Ready:

```json
{"ready":true,"failed_checks":[],"height":194,"peers":1,"secs_since_finalized":2,"max_stall_secs":30,"min_peers":1}
```

Not ready (stalled + peerless):

```json
{"ready":false,"failed_checks":["no_peers","finality_stalled","height_stalled"],"height":194,"peers":0,"secs_since_finalized":187,"max_stall_secs":30,"min_peers":1}
```

`failed_checks` values: `no_peers` (fewer than `min_peers` connections),
`no_finality` (nothing ever finalized), `finality_stalled` (no finalize for
longer than `max_stall_secs`), `height_zero` (height still 0),
`height_stalled` (height not advancing for longer than `max_stall_secs`).

### `GET /metrics` → 200 (Prometheus text)

Consensus registry plus the five gateway gauges (`stell_ready` mirrors
`/readyz`: 1 ready, 0 not; `src/explorer.rs:808-849`). Scrape it, do not
eyeball one value: alert on the derivative of the height (see §2).

```sh
curl -s http://127.0.0.1:8080/metrics | grep -E '^(stell_consensus_height|stell_consensus_round|stell_validator_set_size|stell_fork_total|stell_ready|stellereum_block_height|stellereum_mempool_size|stellereum_contracts_total|stellereum_tokens_total)'
```

```text
# HELP stell_consensus_height Block height the consensus engine is currently working on
# TYPE stell_consensus_height gauge
stell_consensus_height 194
# HELP stell_consensus_round Consensus round currently being voted on at the active height
# TYPE stell_consensus_round gauge
stell_consensus_round 0
# HELP stell_validator_set_size Number of validators in the active consensus validator set
# TYPE stell_validator_set_size gauge
stell_validator_set_size 2
# HELP stell_fork_total Blocks observed that conflict with this node's finalized chain
# TYPE stell_fork_total counter
stell_fork_total 0
# HELP stell_ready Node readiness for serving traffic (1 = ready, 0 = not ready)
# TYPE stell_ready gauge
stell_ready 1
# HELP stellereum_block_height Current finalized block height
# TYPE stellereum_block_height gauge
stellereum_block_height 194
# HELP stellereum_mempool_size Pending transactions in mempool
# TYPE stellereum_mempool_size gauge
stellereum_mempool_size 3
# HELP stellereum_contracts_total Deployed WASM smart contracts count
# TYPE stellereum_contracts_total gauge
stellereum_contracts_total 0
# HELP stellereum_tokens_total Fungible STS tokens count
# TYPE stellereum_tokens_total gauge
stellereum_tokens_total 1
```

---

## 10. Onboarding a new node in one command

> End-to-end validator path (keygen → bond → election → proposing →
> claim → unbond → withdraw, with expected outputs and troubleshooting):
> [`VALIDATOR_ONBOARDING.md`](VALIDATOR_ONBOARDING.md). This section is the
> operator reference it links into.

Two scripts cover both sides. Neither replaces thinking about the genesis
rules in §3 and `testnet/README.md` §0 — they automate the mechanical parts
so there is less room to get those rules wrong.

| side | script | does |
| --- | --- | --- |
| new node (operator) | `scripts/join-network.sh` | generates keys, builds `node.yaml` + env, installs the systemd unit, disk-guard cron and firewall rule, prints the peer-stanza |
| network (admin) | `scripts/add-peer.sh` | appends the stanza to `node.yaml` + `STELL_PEER_PQ_KEYS`, rolling-restarts one unit |

The join script mints a key passphrase and writes it into the node's env file
(0600) — node keys are encrypted at rest, see §11.

Thin CLI behind it: `stellereum keys init` (generate via the same
`load_or_generate` path `run` uses; idempotent, 0700/0600) and
`stellereum keys peer-stanza` (prints node-id/ed-pub/x-pub/falcon-pub).

#### Falcon-512 key migration (pre-FIPS 206 keys)

Every `falcon.key` written before the FIPS 206 (FN-DSA) signer landed is an
INCOMPLETE NTRU key: it carries `f`, `g` and `F` but not the NTRU partner
`G`. Such a key **still loads and still signs** — the partner is
reconstructed in memory exactly as the reference implementation's key
expansion does (`G = g*F*f^{-1} = h*F mod q`) — so:

- the nodes start normally after the upgrade, and
- **the validator address does NOT change** (it is derived from the public
  key `h`, which is never touched), so the on-chain staking set stays valid.

The node logs one loud warning per process when it loads such a key
(`Falcon-512 LEGACY key loaded (pre-FIPS 206, no NTRU partner G on disk)`).
To migrate to a COMPLETE NTRU key at the operator's leisure:

```sh
# backs up the old key to falcon.bak-<unix-ts> and prints the NEW address
# (it prints the CURRENT address first, and refuses without --force)
stellereum keys rotate-falcon --keys-dir ./keys --force
```

Rotation **changes the validator address** (new key ⇒ new public key ⇒ new
address), so re-staking under the new address is a separate, on-chain
operation — do it before the old stake is attributed to the new key.

**The full migration procedure — including what a rotation does to the quorum
while the old bond is still in place — is in [§11.1](#111-the-falcon-512-fips-206-fn-dsa-key-migration).**

### Step 1 — operator: run the join script

```sh
# ONE command. New nodes always start as OBSERVERS (STELL_OBSERVER=1):
# a fresh key must FOLLOW the existing chain, not mint its own genesis.
scripts/join-network.sh \
  --faucet-key <64-HEX-SHARED-WITH-THE-NETWORK> \
  --advertise <PUBLIC_IP:9410> \
  --peers-file <admin-supplied-current-set.yaml>
```

What it does, in order: `keys init` (never overwrites existing keys —
identity is stable across restarts); saves + prints the peer-stanza block
(`peer-stanza.txt`); writes `node.yaml` (template + `peers:`/`validators:`
copied verbatim from `--peers-file`, DNS seeds `seeds.stellereum.org` for
discovery); writes `node.env` (mode 600) with `STELL_OBSERVER=1`,
`STELL_ARCHIVE=0` + `STELL_KEEP_BLOCKS=1000000` (the §1 public-testnet
starting point — archive is unbounded), `STELL_DNS_SEEDS`; installs the
`stellereum-node` systemd unit (`MemoryMax=2G`, `CPUQuota=80%`, `Nice=5`,
journal rate caps + a 500M journald drop-in + logrotate) and a disk-guard
cron (every 15 min, warn ≥80% / crit ≥90%, read-only); opens UDP 9410
(`ufw`, else `iptables`, else prints the command).

Three inputs MUST be right, and the script cannot verify two of them:

- **`--faucet-key` must match every other node byte-for-byte.** It funds the
  faucet account at genesis, so one wrong byte is a different genesis root
  and a private chain (§3, rule (a)). Placeholder values are refused.
- **`--peers-file` must be the network's CURRENT validator set.** Without it
  `node.yaml` ships with empty lists and the unit is installed but NOT
  started — an empty `validators:` derives a solo genesis, which splits
  silently. Ask the admin for a live `node.yaml`, re-run with `--force`.
- **`--advertise` must be diallable.** Autodetect falls back to the LAN IP;
  behind NAT pass the public IP explicitly. QUIC is UDP: `9410/udp` inbound.

Permissions after the run: home + `keys/` 0700, `identity.key` / `e2e.key` /
`falcon.key` / `node.env` 0600. Never commit or paste them; the stanza file
is public keys only and is the one thing you send.

### Step 2 — admin: admit the stanza

```sh
# Observer (default): peers: entry ONLY. Safe: the validator set is unchanged,
# so the genesis root is unchanged and a rolling restart is fine.
scripts/add-peer.sh --node-yaml /root/nodeA/node.yaml --env-file /root/env.A \
  peer-stanza.txt
# ... repeat for every node that should dial the newcomer, then:
scripts/add-peer.sh --node-yaml /root/nodeA/node.yaml --env-file /root/env.A \
  --unit stell-nodeA --restart peer-stanza.txt   # ONE unit at a time
```

Both files are backed up (`*.bak.<UTC>`) before any edit; re-running is a
no-op when the node-id / ed-pub is already present. The `ed:falcon` pair
goes to `STELL_PEER_PQ_KEYS` (comma-separated, env stays 0600).

`--role validator` ALSO appends the id to `validators:`. That CHANGES the
genesis root: every node needs the identical edit and every data dir must be
wiped before restart (the §3 fingerprint guard refuses old data). It is a
COORDINATED chain restart, not a rolling one — the script requires
`--i-understand-genesis-changes` alongside `--restart` and still tells you
to coordinate. See "becoming a validator" below.

### Step 2.5 — first start through the bootstrap gate (no manual copies)

A fresh observer NEVER joins by copying another node's `./data` over ssh
(`cp -a data`): a foreign store carries a foreign genesis fingerprint, and
the node splits silently instead of joining. The supported flow is one
command, from the node home, with the env file sourced:

```sh
cd ~/stellereum-node && set -a; . ./node.env; set +a
stellereum node-bootstrap --config node.yaml --shard 1
```

What it does, in order (`[bootstrap] stage N/4` in the log):

1. **Preflight gate (fail-closed, loud).** Refuses to start unless ALL hold:
   clean data dir (no `store/`/`kv.json` from a previous run — wipe the whole
   `./data`, never single files, §8; `--allow-dirty` is for RESTARTS only),
   `STELL_OBSERVER=1` (a fresh key without it mints its own genesis),
   `STELL_FAUCET_KEY` set (must match the network byte-for-byte),
   a live peer pointer (`peers:` non-empty or `STELL_DNS_SEEDS` set) and a
   non-empty `validators:` (empty derives a solo genesis). `scripts/join-network.sh`
   runs the same gate as `--no-exec` before starting the unit.
2. **Snapshot-sync** (inside the `run` engine this execs into): newest usable
   boundary (exact latest-snapshot pointer when sane), state + EVERY committed
   domain — accounts *including the staking ledger*, `domains`, `session`,
   `bridge`, `confidential`, `zkml`, `cross_shard` — tail-anchored by a
   per-height precommit-QC proof and root-checked BEFORE commit. A stale
   domain blob is rejected with a retry, never committed.
3. **Body walk** of the short remainder (precommit QC verified per height).
4. **Live**: the consensus loop owns the tip (observer follows, never
   proposes/votes).

Every network wait is bounded with honest retries (jittered exponential
backoff, same ladder as the fetch path): a weak link or stale peers delay
bootstrap, never lie to it. The gate is proven by
`tests/node_bootstrap_tests.rs`, which drives a genesis engine to the tip
across dropped snapshots/headers/bodies and one stale `domains` blob.

The systemd unit stays on `run`: the gate runs once at first start, not on
every restart (a restarted node legitimately owns a dirty dir).

### Step 3 — operator: confirm it follows the chain

```
journalctl -u stellereum-node -f   # want: [sync] caught up N blocks to height M
```

```sh
rpc() { curl -s -X POST "$1" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-\{\}}}"; }
rpc http://127.0.0.1:8545 stell_syncing     # true while a verified peer is ahead
rpc http://127.0.0.1:8545 stell_blockNumber # must JUMP toward the peers, not sit
rpc http://127.0.0.1:8545 stell_getStateRoot
```

Compare the last two against a live peer: equal roots at equal heights = one
chain. Same height + different root = split — STOP, do not transact, diff
`STELL_FAUCET_KEY` (by sha256, not by eye) and the `validators:` lists (§3
triage). `stell_getValidators` must show the same `validators` /
`total_power` / `quorum` on both nodes; a newcomer reporting an empty or
zero-power set never enters the consensus loop at all (§4).

### Becoming a validator (two paths, pick one deliberately)

1. **Coordinated genesis rotation** (new chain): admin adds the id to every
   node's `validators:` (`add-peer.sh --role validator` per node), all nodes
   stop + wipe + start together, operator flips `STELL_OBSERVER=0` and
   restarts. Verify identical genesis roots before sending traffic.
2. **Staking bond** (live chain, no wipe): the observer stays
   `STELL_OBSERVER=1`, funds an account via the faucet, bonds stake; the
   runtime re-derives the set from the staking ledger at the height boundary
   (`refresh_validator_set_from_staking`) and its dynamic franchise engages
   without touching anyone's `validators:` or genesis. Fund the account in
   its masterchain form (`stell_faucet` with `"-1:<hex>"`): staking bonds on
   the masterchain, and on a sharded node a bare-address drip executes on the
   workchain — where a staking bond can never be read. A bare-address drip
   against a masterchain-only faucet is refused at admission (shard mismatch),
   never queued.

Never just set `STELL_OBSERVER=0` on a live chain and hope: a key outside the
committed set either derives its own genesis (split) or votes with zero
weight while looking healthy.

### Returning a flown observer WITHOUT `cp` (stale-data node, e.g. C)

A node that sat out a bond/rotation comes back with state on disk whose
ledger predates the bond (live case: C at ~77k with a ledger from before bond
81821, live tip ~93k). The block walk can never teach it the bond — the bond
height is outside every body/header window — so without the repair below it
keeps a foreign set forever: no votes, foreign quorums, looks healthy.
`cp -a data` from a live node is forbidden: a foreign store carries a foreign
genesis fingerprint and splits silently instead of rejoining.

Procedure — clean data, then only the protocol (each step names its check):

```sh
# 0. Stop the unit, wipe the WHOLE ./data (never single files — §8).
systemctl stop stellereum-node
rm -rf ./data   # keep ./keys and node.env (identity + faucet key are genesis inputs)

# 1. Re-run the bootstrap gate (same command as Step 2.5).
cd ~/stellereum-node && set -a; . ./node.env; set +a
stellereum node-bootstrap --config node.yaml --shard 1
```

What must happen, in order, and what proves each transition:

1. **Clean → snapshot (state + domains WITH the bond).** The gate refuses a
   dirty dir, a lost `STELL_OBSERVER=1`, a wrong faucet key, or an empty
   `validators:` — read the named cause, fix it, never route around it with a
   copy. The engine probes the newest usable boundary (exact
   latest-snapshot pointer when sane, else newest `%100` downward, bounded):
   `fetch_state_snapshot` + every `fetch_domain_snapshot` kind, each under
   the generous snapshot budget (20s/chunk, 6 retries/chunk, 15s manifest,
   300s/blob cap) with per-chunk resume. Check: `[sync] fast-synced state
   from a snapshot at height B` in the log, and `stell_getStateRoot` afterwards
   equals a live peer's root at B. A stale `domains` blob (present but
   pre-bond, or garbage) is REJECTED with a retry of the SAME boundary
   (`BOOTSTRAP_MAX_STALE_PER_BOUNDARY` = 3, then one window older) — never
   committed. If the restored ledger lags the state beyond the 300-height
   freshness ring, the node fail-closes to observer with a loud
   `STALE validator set` WARN and repairs the set alone from fresh domain
   snapshots (`refresh_validator_set_from_fresh_snapshot`), moving no blocks.
2. **Snapshot → tail-anchor (gap > 50).** A genesis-anchored (fresh) node, or
   any gap above 50, proves only the trailing 8-header window ending at the
   snapshot successor (`verify_snapshot_anchor_tail`): every height hash-linked
   AND carrying a Precommit QC verified against OUR committed set from the
   scheduled proposer. Check: no `REFUSING snapshot … trailing header proof
   failed` line for the committed boundary; a forged/missing/QC-less header
   anywhere in the window refuses the snapshot. (A non-fresh node with a
   finalized head uses the full walk from its head instead — same per-height
   forgery budget.)
3. **Tail → walk.** The short remainder is walked by bodies
   (`collect_missing_blocks`, hash-checked at the fetch boundary),
   QC-verified per height (`validate_sync_chain_for_shard`), parent-root
   checked BEFORE each apply with fail-fast divergence detection. Check:
   `[sync] caught up N blocks to height M`, then `stell_blockNumber` JUMPS
   toward the peers (not climbs) and `stell_getStateRoot` equals the peers at
   the same height.
4. **Walk → live.** The consensus loop owns the tip; an observer follows and
   never proposes/votes until its ledger is fresh (`effective_can_vote`).
   Check: `/readyz` 200 with empty `failed_checks`, `stell_syncing` false at
   the tip, state root still equal to peers a minute later.

Weak-link honesty: every header/QC fetch retries 3× with backoff, every
snapshot miss paces the probe loop (20ms/miss, cap 200ms), retries are
jittered so slow peers delay bootstrap but never lie to it. On 1vCPU/60% give
a far-behind node tens of minutes, not seconds — watch the stage log
(`[bootstrap] stage N/4`), not the wall clock.

Proven by `tests/observer_return_without_copy_tests.rs`: a genesis engine with
a pre-bond ledger in the starting point reaches the tip over dropped
snapshots/headers/bodies and TWO stale `domains` blobs (one on the set-only
path, one on the fast-sync path) — snapshot WITH the mid-chain bond,
tail-anchored, walked, tip root exact, attempt counters proving the run was
genuinely adversarial. `tests/node_bootstrap_tests.rs` pins the same path
from a clean genesis; `tests/validator_set_freshness_tests.rs` pins the
STALE gate and the set-only repair in isolation.

### Quick symptom map for joins

| symptom | cause | fix |
| --- | --- | --- |
| `genesis state root mismatch` on first start | faucet key or validator set differs from the network | copy both verbatim from the admin; wipe `./data` (never one file — §8) |
| height jumps but root disagrees with peers | same | same |
| height sits at 0, `validator set has no power` | empty/small set (no `--peers-file`, or observer flag lost) | restore the set, keep `STELL_OBSERVER=1` until promoted |
| `view change` loop, roots agree | peer not admitted on the other side / UDP blocked | admin side first, then `ufw allow 9410/udp` |
| `[bootstrap] REFUSING: ...` on first start | preflight gate: dirty data dir, lost `STELL_OBSERVER=1`, unset faucet key, no peer pointer, or empty `validators:` | read the named cause, fix it, re-run `node-bootstrap` — never `cp -a` another node's data/ instead |
| disk climbs 2GB+/day | archive default slipped back in | `STELL_ARCHIVE=0` + `STELL_KEEP_BLOCKS` in the env file, not just the unit |

---

## 11. Node keys are encrypted at rest (default)

The three node private keys live in `./keys` (0700 dir, 0600 files):

| file | what it is | if it leaks |
| --- | --- | --- |
| `identity.key` | Ed25519 signing seed — **the validator identity** | forge votes, impersonate the node |
| `e2e.key` | X25519 static secret for the node-to-node channel | decrypt the e2e traffic of that node |
| `falcon.key` | Falcon-512 post-quantum validator key | forge PQ micro-certificates |

**They are encrypted on disk by default.** The on-disk format is
`enc2:<salt_hex>:<nonce_hex>:<ct_hex>` — Argon2id (64 MiB, t=3, p=4) stretched
over the passphrase, then XChaCha20-Poly1305. A new key is *never* written as
raw hex any more.

The **Falcon-512 validator key** has its own migration story (the pre-FIPS-206
keys are incomplete NTRU keys that still load and keep the address): see
[§11.1](#111-the-falcon-512-fips-206-fn-dsa-key-migration).

### The environment variables

| variable | value | effect |
| --- | --- | --- |
| `STELL_KEY_PASSPHRASE` | any non-empty string | **the passphrase** used to encrypt and decrypt the keys |
| `STELL_NODE_PASSPHRASE` | any non-empty string | historic name for the same thing; checked *before* `STELL_KEY_PASSPHRASE` |
| `INFNODE_KEY_PASSPHRASE` | any non-empty string | oldest fallback, checked last |
| `STELL_KEY_PLAINTEXT` | `1` / `true` / `yes` / `on` | **explicit opt-out**: write the keys in plaintext. Anything else (or unset) keeps them encrypted |
| `STELL_KEY_PROMPT` | `1` | ask for the passphrase on the terminal instead of reading it from the environment. Only used when stdin is a TTY, so a systemd unit never blocks on a prompt |
| ~~legacy-genesis env knob~~ (removed — do not set, inert no-op) | — | REMOVED: Falcon keygen is strict-only with no legacy branch (`stellereum/src/post_quantum.rs:1598-1600`); the env toggle changes nothing (`stellereum/tests/a_crypto_audit_poc.rs:147-174`); genesis-guard suspects no longer list it (`stellereum/tests/genesis_guard_tests.rs:60-64`). |

The first non-empty of `STELL_NODE_PASSPHRASE`, `STELL_KEY_PASSPHRASE`,
`INFNODE_KEY_PASSPHRASE` wins. Setting more than one is a mistake: the extra
value is ignored, and the next start with a different set of variables fails.

### Putting a passphrase on a running node

```sh
# 1. a passphrase file only root can read
install -m 600 /dev/null /etc/stellereum/keys.env
printf 'STELL_KEY_PASSPHRASE=%s\n' "$(openssl rand -base64 32)" > /etc/stellereum/keys.env

# 2. the unit reads it (systemd: EnvironmentFile=/etc/stellereum/keys.env)
#    a shell run: set -a; . /etc/stellereum/keys.env; set +a

# 3. restart the node. The first start re-encrypts the existing keys in place:
#    [node-keys] upgraded ./keys/identity.key to the encrypted enc2: format
```

The passphrase is not recoverable from the key file. **Lose it and the key is
gone**: the node cannot decrypt its own identity, and there is no fallback
path — see "fail-closed" below. Back up the passphrase together with the key
directory, in the same place, with the same 0600 discipline. A backup of
`./keys` without the passphrase is a backup of ciphertext.

### Upgrading an existing plaintext node

Nothing is required. A plaintext key still loads (that is what the live
testnet nodes are running right now), and the moment a passphrase is present
the node rewrites the key file in the encrypted format on the next start. The
identity does not change: the bytes are the same, only the file encoding is.
Check it:

```sh
head -c 5 ./keys/identity.key   # "enc2:" once the upgrade happened
```

If the key is already encrypted and the passphrase is missing, the node does
**not** downgrade it and does **not** fall back to a fresh key. It exits.

### Fail-closed: what it looks like

Two refusals, both fatal, both naming the fix:

```
refusing to write node keys without encryption: no passphrase is available.
Node private keys are encrypted at rest by default (enc2: Argon2id + XChaCha20-Poly1305).
Set STELL_KEY_PASSPHRASE (or STELL_NODE_PASSPHRASE) to a passphrase.
To deliberately store this key in plaintext, set STELL_KEY_PLAINTEXT=1 (explicit operator opt-out — the key file is then readable by anyone who can read the file).
```

```
node key is encrypted (enc2: Argon2id + XChaCha20-Poly1305) but no passphrase is available.
The node refuses to start without it: it will not fall back to a plaintext or default key.
Set STELL_KEY_PASSPHRASE (or STELL_NODE_PASSPHRASE) to a passphrase.
```

The second one is the important one: an encrypted key with a missing (or
wrong) passphrase must never be papered over with a default identity. A node
that silently starts with a *new* key looks healthy and is a different
validator to the rest of the network.

### The escape hatch, and when to use it

`STELL_KEY_PLAINTEXT=1` is for operators who cannot run a passphrase (an
image build that copies keys in, an ephemeral node, a debugging session). It
is a deliberate downgrade: the key file becomes raw hex again and is readable
by anyone who can read the file. It does **not** decrypt an existing
encrypted key — that still needs the passphrase.

Treat it as a last resort. If you use it:

- keep `./keys` at 0700 and the files at 0600 (the node enforces this on
  load and refuses to start otherwise);
- never copy such a node's `./keys` into a container image, a backup tarball
  or a config-management repo;
- plan the migration back: set a passphrase, restart, confirm `enc2:`, and
  drop the flag.

### Quick symptom map for key errors

| symptom | cause | fix |
| --- | --- | --- |
| exit: `refusing to write node keys without encryption` | no passphrase in the environment and the node is generating a key for the first time | set `STELL_KEY_PASSPHRASE`, or `STELL_KEY_PLAINTEXT=1` if you really want plaintext |
| exit: `node key is encrypted ... but no passphrase is available` | the key was encrypted earlier, the passphrase is not in the environment now | export the same passphrase again (check the systemd `EnvironmentFile`) |
| exit: `invalid passphrase for node key` | the passphrase is wrong | check for a trailing newline in the env file; `printf`, not `echo`, when the passphrase contains `\` |
| `[WARN] ... loaded from a PLAINTEXT key file` | no passphrase configured, key is still in the clear | set a passphrase and restart — the node re-encrypts it in place |
| `key file ... has insecure permissions 0o644, expected 0o600` | someone relaxed the mode | `chmod 600 ./keys/*.key` (and `chmod 700 ./keys`) |

---

## 11.1 The Falcon-512 FIPS 206 (FN-DSA) key migration

### What changed

Every Falcon-512 validator key written by the **pre-FIPS-206** code is an
**incomplete NTRU key**: it carries no `G`, the NTRU partner of `(f, g, F)`.
Such a key still loads, still signs and still verifies — the partner is
reconstructed in memory exactly as the reference implementation's key expansion
does — so **the upgrade does NOT force an address change and the live nodes
keep their validator address**.

That is why the migration is not urgent and not automatic: nothing breaks, and
nothing gets better by itself.

### What "better" means

A complete `(f, g, F, G)` key, generated by the authentic reference
implementation, is a key that can be exported, re-imported and re-verified by
another implementation. The incomplete keys cannot: the missing `G` is
reconstructed, so two implementations can disagree about the expansion.

### Do I have to?

- **No, not to keep the chain running.** A legacy key loads, signs and
  verifies today.
- **Yes, if you want the key to be portable**, or if you want to be able to
  prove the key is complete to a third party.
- **Yes, eventually.** A rotation **changes the validator address**, so it is
  an on-chain operation (re-stake under the new address), not a config change.

> **Remote signers do not change this.** The remote signer
> (`STELL_REMOTE_SIGNER_URL`) is **Ed25519-only**: the Falcon-512 vote half
> still comes from the local `falcon.key` file, so a legacy Falcon key is still
> the key that signs, whether the rest of the identity is held in an HSM or
> not (`src/remote_signer.rs`, "HSM GAP").

### How to rotate

```sh
# 1. Back up the key directory first. This is the only copy of your identity.
install -d -m 700 /root/keys-backup-$(date +%s)
cp -a ./keys/. /root/keys-backup-$(date +%s)/

# 2. Rotate. --force is REQUIRED when a key already exists, because the
#    rotation changes the validator address.
STELL_KEY_PASSPHRASE=... stellereum keys rotate-falcon --keys-dir ./keys --force
```

What the command does:

- prints the **current** validator address first (and says whether the loaded
  key is a LEGACY pre-FIPS 206 one);
- **refuses without `--force`** when a key already exists — rotation changes
  the validator address, and the on-chain staking set must be updated for the
  new one;
- generates a fresh, **complete** `(f, g, F, G)` Falcon-512 key with the
  authentic reference implementation;
- backs the old file up next to it as **`falcon.bak-<unix-ts>`** (the
  extension is *replaced*, so `falcon.key` becomes `falcon.bak-1758800000`,
  not `falcon.key.bak-1758800000`), with the same permissions;
- prints the **new** validator address;
- writes the new key in the same on-disk format the node already uses
  (`enc2:` when a passphrase is configured, plaintext only under the explicit
  `STELL_KEY_PLAINTEXT=1` opt-out).

### After the rotation

The **new address is a different validator**. The old bond, the old power and
the old address stay exactly where they are — the rotation moves the *key*,
not the *stake*. To keep the same voting power you must:

1. **bond under the new address** (`stell_stakeBond` / the `staking` CLI),
2. wait for the validator-set rotation at the next height boundary
   (`refresh_validator_set_from_staking`, PROTOCOL.md §2), and
3. only then remove the old key from the network's `validators:` list.

Until step 2 completes, the network sees **one extra validator** (the old one,
still bonded, now unable to sign) — and with a small set that can make the
quorum unreachable. With `N = 3` an extra unfunded-but-bonded validator is
exactly the case §5 warns about. **Do the rotation on a network you can
observe, one node at a time, with the quorum checked before and after.**

### The old key file

The backup (`<file>.bak-<unix-ts>`) is a **plaintext-or-encrypted validator
key**: treat it exactly like the live one. It is not garbage to be deleted —
it is the key that still holds the bond until you re-stake under the new
address.

---

## 12. Software upgrades: `STELL_AUTO_UPGRADE` and the staging rules

A **governance** proposal can schedule a software upgrade at a specific
height: `stell_submitProposal` with `type: "software_upgrade"`, `name`,
`height` and `sha256`. When the node reaches that height and the proposal has
passed, the upgrade fires.

### `STELL_AUTO_UPGRADE`

| value | effect |
| --- | --- |
| unset (the default) | **`0`** — the node **does not** exec the new binary; it halts with exit code 42 and the supervisor restarts it |
| `1` / `true` | the live migration is ARMED: the upgrade is executed automatically (`execve` in place) |
| anything else (`0`, `false`, `yes`, a typo, …) | the node **does not** exec the new binary; it logs the trigger and halts with exit code 42 |

**The default is OFF.** (Changed in audit wave W8.3 — production blocker
A8. The old default was `1`, i.e. "armed unless told otherwise".)

Why: an on-chain governance proposal is a quorum decision about the chain's
**rules**. It is not, and must not be, a decision to replace the running
binary on your box. Under the old default, a quorum decision alone was
enough to make every node `execve` a new binary; the operator had to know to
set `STELL_AUTO_UPGRADE=0` to prevent it. Arming the live migration is
**node-local, operator-local policy**, so it takes a node-local, operator-local
switch — and the safe state is the default one.

Only the two literal spellings `1` and `true` arm it (case-insensitive,
surrounding whitespace ignored). **A typo fails SAFE**: the node halts at the
upgrade height with exit code 42 and the supervisor restarts it; it never
execs a binary nobody asked for.

**When it IS armed, the node says so loudly at start-up** — a banner on
stderr plus a `WARN` line:

```
================= STELLEREUM: LIVE MIGRATION ARMED =================
STELL_AUTO_UPGRADE=1 — LIVE MIGRATION ARMED: at an approved upgrade height this node will
exec() the SHA-256-verified new binary IN PLACE, without a supervisor.
This is operator-local policy: arm it on EVERY node deliberately, or leave
it off everywhere and let the exit-code-42 path do the restart.
==================================================================
```

Arm it on **every** node or on **none**: a network that half-upgraded runs
two binaries.

The proposal still needs its quorum either way — `STELL_AUTO_UPGRADE` does
not stop a proposal from passing, it only stops the node from exec'ing.

### The candidate paths

The plan's `name` is used to build the candidate path. The node tries, in
order:

```text
data/upgrades/<name>/stellereum
data/upgrades/<name>/bin/stellereum
/usr/local/bin/stellereum.new
```

The **first** path that exists and passes the hash check is the one that is
staged.

### The staging rules

These are the rules that make the exec safe. They are enforced by
`governance::stage_verified_upgrade_binary`, and they are the reason an
upgrade proposal cannot be turned into arbitrary code execution on the box.

1. **The name must be a safe single path segment.** `upgrade_name_is_safe`
   refuses: an empty name, a name longer than 64 bytes, any `/` or `\`, a NUL
   byte, any **non-ASCII** character (the Unicode look-alikes survive a naive
   byte check), `.`, `..`, and any name starting with `.` (a hidden
   directory). A name that fails this yields an **empty** candidate list: the
   exec is skipped, and the node still **halts at that height with exit code
   42** (the graceful upgrade halt) — it does not keep running the old
   binary as if nothing had happened.

2. **The candidate must be a regular file, not a symlink.**
   `symlink_metadata` does not follow the link, so a symlinked candidate is
   detected and refused. (A symlink turns "the candidate under the operator's
   upgrade directory" into "any file on the box".) A non-regular file (a
   directory, a fifo) is refused too.

3. **Size cap: 512 MiB** (`MAX_UPGRADE_BINARY_BYTES`). A bigger blob is
   refused before it is read into memory.

4. **The SHA-256 must match, exactly.** The digest is compared with strict
   equality, and the **all-zero** digest is never a match (it is refused at
   propose/execute time as well). Compute it with
   `sha256sum data/upgrades/<name>/stellereum`.

5. **The bytes that were hashed are the bytes that run.** The verified bytes
   are copied into a **fresh private directory** (random name, mode `0700`,
   fsynced) and **that copy** is executed. This closes the TOCTOU: the old
   path read + hashed a file and then exec'd it *by path*, so the file could be
   swapped in between the check and the exec.

6. **The candidate is not chmod-ed.** The old path ran `set_permissions(0o755)`
   on the candidate, which chmod-ed the **target** of a planted symlink. The
   staging copy is created with mode `0700` instead, and the candidate is left
   alone.

7. **The candidate's PARENT directory must be a real directory** (audit W8.3,
   the residual the W6.7 re-audit did not cover). The candidate FILE was
   checked for being a symlink, but its parent was not: a symlinked parent
   (`data/upgrades/v1.0.0` → `/etc`) turns "the candidate under the operator's
   upgrade directory" into "a file somewhere else on the box". The hash check
   still protects the CONTENT, but the sandbox the operator believes they have
   would not exist. A symlinked parent is refused loudly, fail-closed.

### What it looks like

```
[upgrade] UPGRADE TRIGGERED at height 12345: plan name='v0.2.0', target sha256=3f9a…
[upgrade] found verified new binary at "data/upgrades/v0.2.0/stellereum" (sha256 matches) — executing live zero-downtime swap!
```

A refused upgrade says so explicitly:

```
[upgrade] REFUSING upgrade plan '…': the name is not a safe path segment
```

and a candidate that fails one of the staging rules is named individually:

```
[upgrade] candidate "data/upgrades/v0.2.0/stellereum" refused: upgrade candidate … sha256 mismatch (expected …, got …)
[upgrade] candidate "…/stellereum" refused: upgrade candidate … is a SYMLINK: refusing (the candidate must be a regular file)
```

Either way the node halts at that height with **exit code 42**, which is the
signal your supervisor should treat as "upgrade time": stage the binary, then
let the supervisor restart it.

### Operator checklist before you ratify

```sh
# 1. Stage the binary under a SAFE name.
install -d -m 700 data/upgrades/v0.2.0
install -m 755 /path/to/new/stellereum data/upgrades/v0.2.0/stellereum

# 2. Compute the digest and put it EXACTLY in the proposal.
sha256sum data/upgrades/v0.2.0/stellereum

# 3. Make sure the candidate is a regular file, not a symlink.
test -L data/upgrades/v0.2.0/stellereum && echo "REFUSED: symlink"

# 4. Decide whether you want the automatic exec.
#    STELL_AUTO_UPGRADE=0 (or unset) on every node -> the node halts with
#    exit code 42 at the upgrade height and your supervisor restarts it.
#    STELL_AUTO_UPGRADE=1 on every node -> the node execs the new binary
#    IN PLACE (no supervisor involved). Arm it DELIBERATELY: the node
#    prints a LOUD banner at start-up when it is armed.

# 5. Stage the SAME bytes on EVERY node before the upgrade height.
```

**Stage the same bytes everywhere.** The proposal carries one digest; a node
whose candidate does not match simply does not upgrade, and the network ends
up running two binaries. The node does not fall back to
`/usr/local/bin/stellereum.new` after a hash mismatch on the first candidate —
the mismatch ends that candidate; the next path is tried only if the file does
not exist.

### Rollback after a failed `SoftwareUpgrade`

The upgrade path stages forward; this is the tested way back. There is no
automatic downgrade — an automatic rollback would re-execute whatever binary
happens to be lying around, which is the same class of mistake the staging
rules exist to prevent.

**1. Pin the previous binary before every upgrade (do it now, not during
the incident).** There is no `.old`-suffix convention in this tree — the
supported pattern is the atomic deploy plus a backup tarball, both already
in this document:

```sh
# atomic deploy, never cp over a running binary (ETXTBSY risk, §7.2):
cp /path/to/new/stellereum ./stellereum.new && mv ./stellereum.new ./stellereum
# keep the running (previous) binary AND a restorable state backup (§8):
cp ./stellereum ./stellereum.prev-<OLD-VERSION>
scripts/backup/backup.sh --node A   # tarball: node.yaml + data/ + keys/ + env
```

Verify the pin before the upgrade height: `sha256sum` the staged candidate
against the proposal digest, `test -L` against symlinks (§12 staging
rules), and confirm the tarball lists its four members (`tar -tzf`).

**2. State-compat check: prove the old binary can read the current state
before you roll back to it.** State layout that matters:

- live state snapshots: written every `STELL_SNAPSHOT_INTERVAL` heights
  (default **1000**, minimum 50; `src/main.rs:157-159`,
  `src/storage.rs:1405`), archive proofs served only at snapshot heights;
- retained-block / snapshot ring: the 100-height cadence job (§1) with
  `PRUNE_BATCH` = 20 000 bodies per pass — a node far behind the boundary
  converges gradually, not instantly.

Checklist (all read-only; the node must be STOPPED for the store reads
because sled holds an exclusive lock, §15.5):

```sh
# a. the store's view of itself (build once, offline, sled-only):
cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml
scripts/tools/stelops/target/release/stelops checkpoint /root/nodeA/data/store
scripts/tools/stelops/target/release/stelops genesis-root /root/nodeA/data/store
# b. the network's view (from a healthy peer, or a second node):
curl -s -X POST $PEER_RPC -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_getStateRoot","params":{}}'
curl -s -X POST $PEER_RPC -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":{}}'
```

Rollback is safe when (a) the `genesis-root` matches the network's genesis
(same chain, §3) and (b) the old binary's genesis constants
(`GENESIS_VALIDATOR_BALANCE`, `GENESIS_FAUCET_BALANCE`, genesis bond,
`COMMITMENT_VERSION` — §3) match the binary that wrote the store. If (b)
fails, the old binary exits with `genesis state root mismatch` on start —
that refusal is the safety net, not a bug: restore the matching binary
instead of wiping (§3, §8 "Fingerprint mismatch").

**3. Exact rollback sequence.**

```sh
systemctl stop stell-nodeA                                   # stop first: hot tarballs catch sled mid-write (§8)
scripts/backup/restore.sh /root/backups/stell-nodeA-<pre-upgrade-ts>.tar.gz A
# restore.sh refuses over a live node, snapshots current state to
# pre-restore-nodeA-<ts>.tar.gz first, and does NOT start the node (§8)
./stellereum.prev-<OLD-VERSION> --version                    # sanity: the right old binary
install -m 755 ./stellereum.prev-<OLD-VERSION> ./stellereum  # via the atomic deploy pattern above
systemctl start stell-nodeA && journalctl -u stell-nodeA -f
# want: [sync] caught up N blocks (body walk) or straight into finalizing;
# compare stell_getStateRoot + stell_blockNumber against a healthy peer (§10 Step 3)
```

**4. Recovery-time expectations (honest).** Restart drain + sled lock
release is ~15–20 s (§7.2: allow 30 s poll-to-zero before SIGKILL). Past
that, recovery is bounded by how far the node must walk: the body walk
replays only the tip window (200 000 blocks max, §4), with jittered
exponential-backoff retries on weak links (bootstrap gate, §10) — minutes
for a short stall, longer for a node that sat out the upgrade height and
must snapshot-sync state + every domain first. The exit-code-42 path is the
same supervisor restart either way: unarmed nodes halt at the upgrade
height and the supervisor restarts them (§12), so a *failed* upgrade and a
*refused* upgrade converge on the same recovery procedure. If the network
half-upgraded (some nodes on the new binary), rollback is **coordinated**:
every node back to the same binary + matching state, or the network runs
two binaries and the proposal digest matches none of them.

---

## 12.1 The external light client (`stellereum light-client`)

Audit wave W8.3 closed production blocker A10: the light client used to be a
library nothing called, so the only thing an outside verifier could get was
"the root the node says it believes in". It is now a real, usable external
verifier (the Near `light_client` / Sui `sui_light_client` model) **and** it is
wired into the node's own sync path.

### What the node now serves

| RPC | what it returns | why it matters |
| --- | --- | --- |
| `stell_getFinalizedHeader {height}` | the finalized header at that height **with its precommit quorum certificate** | The certificate is what makes the header's state root trustworthy. Without it the root is the server's word. |
| `stell_getFinalizedCheckpoint` | the node's newest quorum-certified header (its anchor) | A client re-anchors here; the anchor only ever moves forward. |
| `stell_getProof {address}` | an inclusion/exclusion Merkle proof against the node's **current** state root | The proof itself. |

### The chain's root convention (read this once)

A Stellereum block header commits to the state **before** its own block (the
state it builds on). So:

* the header at height `H` commits to the root of the state at height `H-1`;
* the node's live proofs are served against the **current** state, so the
  header that commits to them is the one at height `H+1`.

That is why the client anchors a served proof with the header at `height + 1`
— it is the first header a quorum certified for that root. The client waits
for it (the node has to finalize one more block) and says so plainly if it
never arrives.

### Using it

```sh
# 1. Pin the validator set OUT OF BAND. This is the trust anchor: a set
#    taken from the server at verification time is circular.
curl -s -X POST http://127.0.0.1:8545 \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_getValidators","params":{}}' \
  | jq '.result' > validators.json
#    ... review it, publish it, pin it. Do NOT take it from the node you are
#    verifying at verification time.

# 2. Verify an account.
stellereum light-client \
  --from http://127.0.0.1:8545 \
  --verify 3f2a...9c \
  --validators validators.json \
  --wait-seconds 30
```

What the command does, in order:

1. loads the pinned validator set (an empty set is **refused**: no quorum
   certificate could ever be verified against it);
2. fetches the proof from the node's RPC;
3. fetches the header at `height + 1` — the header that **commits to** the
   served root — waiting (bounded by `--wait-seconds`) for the node to
   finalize it;
4. checks that the header really commits to the served root;
5. checks the header's precommit quorum certificate against the pinned set:
   a real quorum of real validator power, bound to that height and hash. A
   prevote quorum is **not** finality and is refused;
6. checks the Merkle proof itself against the now-trusted root.

A refusal is loud and says which step failed. The exit status is non-zero.

### What it does NOT prove

* **The validator set is the entire trust anchor.** If the set is wrong, or a
  quorum of it is Byzantine, everything the client concludes is wrong — and
  it concludes it confidently. There is no validator-set rotation story here.
* It does not verify that a header's state root was computed from the block
  body (that needs execution); it verifies that a QUORUM committed to the
  header that commits to the root.
* It does not fetch anything by itself beyond the two RPC calls above.

### Inside the node

The node keeps a light client of its own, anchored at the chain's genesis
(trusted by construction — the node built that genesis) and moved up to its
own quorum-certified finalized head on every finalize. Every block a peer
offers during a sync is checked against that anchor **before** it is applied:
the chain must continue the anchor (height + 1, hash linkage), every block
must carry a precommit certificate that verifies under the node's committed
validator set, and the state root must not roll back.

---

## 12.2 What the zkML opcodes actually do (`stell_zkmlCapabilities`)

Audit wave W8.3 closed production blocker A5 ("zk-SNARK ❌ не настоящий ZK").
The short version: **the chain does not offer zero-knowledge proofs, and it
now says so in machine-readable form.**

```sh
curl -s -X POST http://127.0.0.1:8545 \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_zkmlCapabilities","params":{}}' | jq .
```

The answer says, in data:

* `zero_knowledge: false`, `succinct: false`, `hiding: false`,
  `trusted_setup: false`, `sound: true`;
* `protocol: "verifiable-inference-by-re-execution"`;
* per opcode: what it really does, what it trusts, and how much work the
  verifier does.

Both §2 verify opcodes work by **re-executing** the committed quantized model
on the proof's public inputs and comparing the outputs and the BLAKE3 trace
root. That is **sound** — a forged proof with invented activations and lying
outputs is rejected — but it is not succinct (the verifier runs the whole
model) and not hiding (the inputs and the outputs are in the clear).

### The opcodes were renamed, because the old names lied

| old name | new name | what it does |
| --- | --- | --- |
| `SysCallVerifyZkMlIn` | **`SysCallVerifyZkMlReexec`** | verify by re-execution against the registered model |
| `SysCallVerifyZkMlSnark` | **`SysCallVerifyZkMlAttestation`** | the same re-execution, additionally bound to a registered model spec |
| `SysCallRegisterZkMlVk` | **`SysCallRegisterZkMlSpec`** | register the model's constrained format + I/O shape + a setup **label** |

The wire discriminants are unchanged (35, 37, 38) — only the names moved, so
a payload signed before the rename still decodes. The "verifying key" that
used to be registered was never a Groth16 key: it is the model's constrained
format plus a free-form setup label, and there is no ceremony behind it.

**Do not market this subsystem as "zk" or "SNARK".** It is *verifiable
inference by re-execution*. A wallet that needs to know the difference should
read `stell_zkmlCapabilities`, not the opcode names.

---

## 13. Environment variables that changed

These are the variables an operator is most likely to still have at their old
value (or not have at all) after the remediation wave. **None of them is
consensus**: they are node-local policy, so two nodes may differ without
splitting the chain — but they will behave differently, which is its own kind
of incident.

| variable | default | what it does | what to do |
| --- | --- | --- | --- |
| `STELL_ROUND_TIMEOUT_MS` | **3000** | how long a node waits before moving to the next consensus round. Clamped to **200 … 3 600 000** ms. | On a LAN (validator set on one host, millisecond RTTs) the default dominates every measurement: a height that needs ~10 missed rounds costs 30 s. Set it to **500** or lower for a single-host cluster. On a WAN keep the default; a 2–11 s-latency third validator can never coincide with a fast local one at the old ceiling, which halts a 3-member chain outright. |
| `STELL_ROUND_ZERO_TIMEOUT_MS` | **650** | the round-0 propose wait when no proposal has landed | Lower it if your proposer is slow to answer in round 0; raise it if your proposer's first proposal is being timed out before it lands. |
| `STELL_DOWN_PROPOSER_TIMEOUT_MS` | **800** | the fast view-change timeout used when the scheduled proposer is **known to be down**. Ignored when the value is `0` or unparseable. | Keep the default. Raising it delays the recovery of a downed proposer; lowering it causes view changes on a merely slow proposer. |
| `STELL_BROADCAST_JOIN_MS` | **500** | the flush join budget of the consensus broadcast: the flush returns after this even if some peers have not acknowledged. | Raise it on a high-latency network so a slow peer does not delay every round; lower it when a single slow peer is stalling the round. |
| `STELL_SHARDS` | unset (single shard) | the shards **this process** runs, e.g. `STELL_SHARDS=0,1` runs the masterchain **and** workchain 1 in one process. | Set it on **every** process that is supposed to host a workchain. A process that hosts a shard it does not know about, or that is missing a shard it hosts, will not converge. |
| `STELL_WORKCHAIN_OBSERVER` | unset | when `1`, this process **observes** the workchain instead of validating the masterchain against it | Set it on a node that follows a workchain but does not produce masterchain blocks for it. A node that is supposed to validate but has this set will not vote. |
| `STELL_ESTIMATE_FEE_RATE_LIMIT` | **5** | the per-IP budget (requests per second) for `stell_estimateFee`, which clones the whole engine state and runs a full SVM simulation | The default is deliberately tight (the generic per-IP budget is 300/s on the standalone RPC). Raise it only for a wallet farm, and only on the node that serves it. |
| `STELL_AUTO_UPGRADE` | **unset (= OFF)** | arms the LIVE MIGRATION: at an approved (quorum-ratified) software-upgrade height the node `execve`s the SHA-256-verified new binary **in place**, without a supervisor. | **Changed in W8.3: the default is now OFF** (it used to be ON). Unset → the node halts with exit code 42 and the supervisor restarts it. Set it to `1`/`true` ONLY on every node of the network, deliberately — the node prints a LOUD banner at start-up when it is armed. A typo fails safe (see §12). |

### What did **not** change

- `STELL_CHAIN_ID` (default **5757**) is now **frozen** the first time it is
  read, and it is bound into every vote preimage and every block hash. A node
  that is restarted with a **different** `STELL_CHAIN_ID` is on a different
  chain and its votes and blocks will not verify against the others. Changing
  it is not a config tweak — it is a new network (see PROTOCOL.md §2a).
- `STELL_ARCHIVE` / `STELL_KEEP_BLOCKS` — unchanged (§1).
- `STELL_RPC_AUTH_TOKEN` — unchanged in name, but it now gates **three more
  methods**: `stell_submitProposal`, `stell_vote` and `stell_executeProposal`.
  If a governance tool of yours started failing with `-32001`, that is why.
- `STELL_KEY_PASSPHRASE` — unchanged in name (§11); the on-disk format is
  `enc2:` and a plaintext key still loads.

---

## 14. Failure-mode runbook

Four symptoms, four checklists. Each one starts with the cheapest check.

### 14.1 The chain stops finalising

**Symptom.** `stell_blockNumber` is flat on every node; the log repeats
`[consensus] view change -> height N round R`; `stell_mempoolSize` is
non-zero and static.

**Checklist, in order.**

1. **Is the quorum reachable?**
   ```sh
   curl -s -X POST "$RPC" -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"stell_getValidators","params":{}}'
   ```
   Read `validators`, `total_power`, `quorum`, `fragile`, `fragile_reason`.

   - `quorum == validators.length()` → **every** validator must sign, and one
     absence halts the chain. See §5.
   - `fragile: true` → the quorum needs **100 %** of the set. The reason
     string says why (typically an `N = 3` equal-stake set, whose quorum is
     3/3).
   - `total_power == "0"` or `quorum == "18446744073709551615"` → the set is
     empty or zero-power. The chain **cannot** finalise, by design. Check the
     `validators:` list against the running keys (§3).

2. **Do the nodes agree on the chain?**
   ```sh
   curl -s -X POST "$RPC" -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"stell_getStateRoot","params":{}}'
   ```
   Same root + same height = same chain. Different roots = a split; go to
   step 5.

3. **Is the node hearing peers?**
   ```sh
   curl -s "$GATEWAY/readyz" | jq .
   ```
   `failed_checks` ⊆ `no_peers,no_finality,finality_stalled,height_zero,height_stalled`.
   `no_peers` → a transport problem, not a consensus problem.

4. **Are the proposers being rejected?**
   ```
   [consensus] rejected proposal from <peer> at #N rR: <reason>
   ```
   The reason names the check. The new ones you will see:
   - `proposal: transaction order does not match the committed order root` →
     a proposer built a body whose order root is stale (a mixed-version
     cluster, or a Byzantine proposer). See PROTOCOL.md §5.2.
   - `proposal: shard heads published by a non-masterchain block` or
     `proposal: shard head set is not canonical` → a shard-header commitment
     problem. See PROTOCOL.md §5.1.
   - `proposal: block gas limit exceeded` → a block over
     `MAX_BLOCK_GAS` (500,000,000).
   - `proposal: tx N from <addr> below fee floor (gas_limit X < floor Y = base …
     + penalty … + pq_surcharge …)` → the proposal carries an **underpriced**
     transaction. The floor is the consensus floor, so every validator that
     refuses it refuses it identically (see PROTOCOL.md §4c).

5. **Is it a split?** Compare `stell_getStateRoot` and
   `stell_blockNumber` across nodes. Different roots on the same height mean
   two chains. The usual cause is a different `validators:` list or a
   different `STELL_CHAIN_ID` on one node. Do **not** "fix" it by wiping a
   data directory without knowing which chain is the real one.

6. **Is the round timing wrong for your topology?**
   ```sh
   grep -E 'STELL_ROUND_TIMEOUT_MS|STELL_DOWN_PROPOSER_TIMEOUT_MS' /etc/stellereum/*.env
   ```
   On a LAN, `STELL_ROUND_TIMEOUT_MS=3000` (the default) makes a missed round
   cost 3 seconds; a height that needs ten of them costs 30 seconds, which
   looks exactly like a stall. See §13.

7. **Was the node restarted with a stale round?**
   ```
   [consensus] resumed checkpoint at height N round R
   ```
   Two nodes deadlocked at different rounds resume at different rounds and
   stay deadlocked. The recovery is a **coordinated** wipe of both data
   directories (§7.2).

### 14.2 The node refuses its key

**Symptom.** The node exits at startup with one of:

```
refusing to write node keys without encryption: no passphrase is available. …
node key is encrypted (enc2: Argon2id + XChaCha20-Poly1305) but no passphrase is available. …
invalid passphrase for node key
```

**Checklist.**

1. **Is the passphrase actually in the environment of the *process*?**
   ```sh
   systemctl show stell-node.service --property=Environment | tr ' ' '\n' | grep -i passphrase
   ```
   A passphrase in your shell is not in the unit's environment. With systemd,
   the passphrase belongs in an `EnvironmentFile=` (`/etc/stellereum/keys.env`).
   With a shell run: `set -a; . /etc/stellereum/keys.env; set +a`.

2. **Is the passphrase the *same* one?** The `enc2:` blob is encrypted with a
   KDF; a wrong passphrase produces `invalid passphrase for node key`, not a
   silent fallback. Watch out for a **trailing newline** in the env file: use
   `printf`, not `echo`.

3. **Are more than one passphrase variable set?** The first non-empty of
   `STELL_NODE_PASSPHRASE`, `STELL_KEY_PASSPHRASE`, `INFNODE_KEY_PASSPHRASE`
   wins; the others are ignored. Setting more than one is a mistake, and the
   next start with a different set fails.

4. **Do the file modes match?** The node refuses to start if a key file is
   group- or world-readable:
   ```
   key file … has insecure permissions 0o644, expected 0o600
   ```
   ```sh
   chmod 700 ./keys && chmod 600 ./keys/*.key
   ```

5. **Do you have the passphrase at all?** It is **not recoverable** from the
   key file. If it is gone, the key is gone: the node cannot decrypt its own
   identity and there is no fallback path. Restore from the backup of the
   passphrase **and** the key directory together (§11) — a backup of `./keys`
   without the passphrase is a backup of ciphertext.

6. **Do you actually want the downgrade?** `STELL_KEY_PASSPHRASE` is the
   supported path. `STELL_KEY_PLAINTEXT=1` is an explicit opt-out that makes
   the key readable by anyone who can read the file; it does **not** decrypt an
   already-encrypted key. Plan the migration back (§11).

### 14.3 A shard stalls

**Symptom.** The masterchain keeps finalising, but one workchain's height is
flat; or the masterchain itself stalls right after a shard transition.

**Checklist.**

1. **Which shard is flat?**
   ```sh
   curl -s -X POST "$RPC" -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"stell_getShards","params":{}}'
   ```
   Each entry has `shard_id`, `type`, `tip_height`, `tip_hash`, `state_root`
   and `local`. A shard that is **not listed** is one this node has not
   committed anything for.

2. **Is the process supposed to host that shard?**
   ```sh
   grep STELL_SHARDS /etc/stellereum/*.env
   ```
   `STELL_SHARDS=0,1` means masterchain **and** workchain 1 in this process.
   A process that is missing a shard it is supposed to host will never
   finalise it. A process that hosts a shard nobody else knows about will
   finalise a chain of its own.

3. **Is the node observing instead of validating?**
   `STELL_WORKCHAIN_OBSERVER=1` makes the node **observe** the workchain
   instead of validating the masterchain against it. A node that is supposed
   to vote but has this set will not vote — and with a small set that is the
   difference between a stall and a quorum.

4. **Is the masterchain committing that shard's head?**
   A masterchain block carries the shard-head commitment (PROTOCOL.md §5.1).
   Look for:
   ```
   [consensus] rejected proposal …: proposal: shard heads published by a
   non-masterchain block
   [consensus] rejected proposal …: proposal: shard head set is not canonical
   [consensus] rejected proposal …: proposal: shard N head at height H contradicts the finalized header
   ```
   The third one is a **shard-chain equivocation**: the proposer published a
   head for a shard at a height this node already finalised with a different
   hash or root.

5. **Is the address→shard rule the one you think?**
   ```sh
   curl -s -X POST "$RPC" -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"stell_getShardTopology","params":{}}'
   ```
   `prefix_bits` is the routing prefix as a bit string; `parameters` carries
   the published thresholds (`min_accounts_per_shard`, `max_shards`,
   `split_load_threshold`, `merge_load_threshold`, `max_prefix_bits`). The
   **shipped** cap is `max_shards = 16`; the advertised address space is
   2^60. They are different numbers and are reported separately.

6. **Is the cross-shard transport working?** A stuck shard is often a stuck
   *message*. The `XSHARD_REPLAY_V1` domain commits the consumed/produced
   sets; a node whose consumed set was wiped can credit a message twice.
   Check the logs for cross-shard rejections before restarting anything.

### 14.4 The indexer falls behind

**Symptom.** The explorer shows a tip height below the node's; the indexer's
logs show it re-syncing; the contract/events pages are empty or stale.

**Checklist.**

1. **Compare the two tips.**
   ```sh
   # node
   curl -s -X POST "$RPC" -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":{}}'
   # indexer
   curl -s "$INDEXER/api/v2/status" | jq '.tip_height, .synced'
   ```
   `scripts/stell-sync.sh health` prints both, plus the validator set, the
   shard heads and the RPC round-trip latency, in one screen.

2. **Is the indexer pointed at the right node?** The indexer reads the node's
   RPC. A node that is **behind** (or on a different chain) produces an
   indexer that is behind. Check the indexer's configured RPC URL.

3. **Is the node itself behind?** If the node's tip is also below the network
   tip, this is a **node** problem, not an indexer problem: go to §14.1.

4. **Is the indexer connected but slow?** A lag that shrinks steadily is a
   throughput problem (the indexer is replaying history). A lag that does
   **not** shrink is a stall: check the indexer's own logs and its database
   for a full-disk error.

5. **Is the disk full?** The indexer keeps its own store; a full disk stops
   the writer silently on some backends. Check the indexer's data directory.

6. **Are the events missing rather than late?** The event endpoints
   (`/api/v2/events`, `/api/v2/contract/:address/events`,
   `/api/v2/tx/:hash/events`) read the **indexer's** event store, which is
   populated from the node's receipts. An empty events page with a correct tip
   usually means the ABI is unknown (`/api/v2/overview` → `abi.known_contracts`)
   or that the contract emitted no events — not a sync problem.

7. **Do not "fix" a lagging indexer by wiping it.** Restarting the indexer
   re-reads from the node and re-derives the history; wiping its database
   loses the history it cannot re-derive cheaply.

### 14.5 The health command

```sh
# from the node's own directory (the stable path):
scripts/cluster_health.sh

# or the cluster tooling itself, from the monorepo root:
scripts/stell-sync.sh health

# with explicit endpoints:
scripts/stell-sync.sh health --rpc http://127.0.0.1:8545 \
                               --indexer http://127.0.0.1:8081
```

It prints, in this order:

1. the **validator set** with each member's power, the total power and the
   quorum (and whether the quorum is `fragile`);
2. the **shard heads** (per shard: type, tip height, tip hash, local or not);
3. the **chain tip per shard**;
4. the **indexer tip**;
5. the **RPC round-trip latency** (median of a few `stell_blockNumber` calls).

Exit code is `0` when every check passed and `1` when any of them did not, so
it can be used as a cron/alert probe.

---

## 15. Что делать, когда сеть встала (the network is down — the runbook)

> **Коротко (RU).** Сеть встала по одной из пяти причин, и ни одна из них
> не видна в логах ноды. Раздел 15 описывает инструменты и порядок действий:
> `preflight` (fail-closed проверка конфигурации перед деплоем), `health`
> (состояние кластера), `doctor` (диагностика одной ноды), `lockclear`
> (сброс залипшего consensus lock), `node-prune-cron.sh` (сборка мусорных
> чанков) и `cluster-watchdog.sh` (сторож с автопочинкой). Начинать всегда с
> `stell-sync.sh preflight` и `stell-sync.sh health`.

Everything in this section was written in response to five real incidents
during the 4-validator deployment attempt. **Every one of them was invisible
in the node's own logs.** That is the whole point of the tooling: the
operator has to be able to ask the cluster questions the cluster does not
answer on its own.

| # | What happened | How it looked from the outside | The tool that catches it |
| --- | --- | --- | --- |
| 1 | Node C's disk filled with 463 589 **orphan chunk files** — all 655 360 inodes consumed (`df -i` = 100 %), so the node went read-only and **silently dropped out of consensus**. Node A had a prune cron; **C never did**. | Nothing. The node was "up" and answering RPC. | `health` (inode %, orphan count), `node-prune-cron.sh`, `cluster-watchdog.sh` |
| 2 | `env.C` had `STELL_SHARDS` regressed to `0` while the other nodes had `0,1`. The pubsub topic is derived from `registry.is_sharded()`, so node C was on a **different topic** and never exchanged a single masterchain message. | Nothing. Zero log evidence. A validator isolated from the network. | `preflight`, `topic`, `doctor` |
| 3 | Node C carried a **stale consensus lock** (height 285 028, round 56) and resumed at round 56 while its peers were at round 0. The rule "never adopt a peer's round" means it could never rejoin. | The node was up, on the right topic, and never finalised. | `lockclear`, `doctor` (the checkpoint), `cluster-watchdog.sh` (stall) |
| 4 | A `cargo clean` in the shared target directory **deleted the running binary** under a live node → the node crash-looped on 203/EXEC. | `status=203/EXEC` in the journal, `ExecMainStatus=203`. | `preflight` (binary outside the target dir), `health` (crash-loop detection) |
| 5 | Node B was **down and crash-looping** at the start of the deployment. Nobody noticed. | Nothing. | `health`, `cluster-watchdog.sh` |

### 15.1 The tool map

All of it lives in `scripts/` at the repository root:

| Script | What it does | Writes? |
| --- | --- | --- |
| `scripts/stell-sync.sh preflight` | **Fail-closed** pre-deploy gate. Names every difference between the nodes and refuses to deploy. | no |
| `scripts/stell-sync.sh health` | The operator health screen + the per-node **cluster table** (service state, inode usage, orphan chunks, pubsub topic, consensus lock, binary path + hash, last exit code). | no |
| `scripts/stell-sync.sh topic <node>` | The pubsub topic a node uses, and the one it should be on. | no |
| `scripts/stell-sync.sh lockclear <node> [--force]` | Clears a stale consensus lock safely. | **yes** (the store) |
| `scripts/stell-sync.sh doctor [node] [--json]` | Single-node diagnosis (also runs standalone on a node: `scripts/doctor.sh`). | no |
| `scripts/node-prune-cron.sh` | The orphan-chunk + snapshot retention sweeper. Run it on **every** node. | **yes** (deletes garbage) |
| `scripts/cluster-watchdog.sh` | Watches the cluster on an interval, alerts, and auto-heals the safe cases. | **yes** (restarts, prunes) |
| `scripts/tools/stelops/` | The ops tool that reads the store (consensus checkpoint, genesis root) and clears the lock. | **yes** (the lock only) |
| `scripts/cluster-nodes.conf` | The cluster topology: who is where, which unit runs it, which env file holds its parameters, and the values every node MUST agree on. | no |

Every script takes `--help`, is non-interactive, and is safe to run
concurrently on several nodes.

### 15.2 The runbook

**Step 0 — the two questions that explain 90 % of the incidents.**

```sh
cd /home/imm/stellereum-project
scripts/stell-sync.sh preflight        # fail-closed: names every difference
scripts/stell-sync.sh health           # the cluster table
```

`preflight` exits non-zero and lists, by name:

* a node that is unreachable (ssh or RPC);
* a node on a **different pubsub topic** (or whose `STELL_SHARDS` differs);
* a different **chain id** or a different **genesis root** (= a different
  chain epoch = a different topic);
* a different `STELL_ROUND_TIMEOUT_MS` / `STELL_DOWN_PROPOSER_TIMEOUT_MS` /
  `STELL_MIN_BLOCK_MS` / `STELL_KEEP_BLOCKS` / admission base fee;
* **inode usage** above the threshold (the read-only filesystem of incident 1);
* a **binary inside a cargo target dir** (the `cargo clean` hazard of
  incident 4);
* a service that is not **enabled** (it will not come back after a reboot) or
  not **active**.

**If `preflight` fails, do not deploy.** Fix the config, re-run, deploy.

**Step 1 — the chain is not advancing.** `health` shows the tip. If the tip
is flat on every node, the cluster is in a view-change storm (incident 3) or
the validator sets differ. Check the per-node lock:

```sh
scripts/stell-sync.sh doctor C          # the consensus checkpoint, the topic, the drift
```

**Step 2 — a node is DOWN or crash-looping.** `health` says `DOWN` or
`CRASH-LOOPING`:

* `CRASH-LOOPING(203/EXEC)` → the binary is gone or not executable. This is
  the `cargo clean` signature: the binary was inside a cargo target dir.
  Move the binary out (`cp /root/stellereum/target/release/stellereum
  /root/stellereum/stellereum`), point the unit's `ExecStart` at it, restart.
* `DOWN` → `systemctl status` and `journalctl -u <unit> -n 200`. The
  watchdog restarts a dead service automatically; a unit that will not stay
  up needs its data dir checked (`doctor`).

**Step 3 — the inodes are running out (incident 1).**

```sh
ssh <node> 'df -i /root/nodeC/data'          # the number that matters
ssh <node> 'scripts/node-prune-cron.sh --dir /root/nodeC --dry-run'
ssh <node> 'scripts/node-prune-cron.sh --dir /root/nodeC'
```

The sweeper deletes only the chunk files that no manifest points at any more
and that are older than the grace period (6 h by default — the node persists
`kv.json` with a debounce, so a recent chunk may not be in the index yet). It
never touches the head pointer's chunks or the active snapshot's chunks: those
are referenced by a live manifest. Install it as a timer on **every** node
(§15.6) — a single node without the timer is a single point of failure.

**Step 4 — the node is on the wrong topic (incident 2).** This is a CONFIG
error, never an auto-heal: the machine cannot guess the operator's intent.

```sh
scripts/stell-sync.sh topic C
#   expected topic  : stellereum/consensus/v1/<epoch>/shard/1
#   subscribed topic: stellereum/consensus/v1/<epoch>      <-- MISMATCH
```

Fix `STELL_SHARDS` in the node's env file to match the rest of the cluster
(`0,1`), restart the node, and re-check. Note the topic is
`.../<epoch>/shard/<id>` when the shard set has more than one shard, and
`.../<epoch>` when it has exactly one: that is why `STELL_SHARDS=0` on one
node put it alone on a different topic.

**Step 5 — the node is stuck on a stale lock (incident 3).** The lock lives
in the store, and sled holds an **exclusive** lock on the store while the node
runs, so it can only be read with the node stopped:

```sh
scripts/stell-sync.sh lockclear C            # the plan; the node is NOT touched
scripts/stell-sync.sh lockclear C --force    # stop, verify, clear, start
```

The tool refuses when the lock is **not** ahead of the peers' tip (a node
whose lock is behind is not stuck because of the lock) and it never touches
the finalized pointer — the node keeps its finalized head and only loses the
stuck lock. The removed bytes are backed up next to the store as
`consensus-checkpoint.bak.<ts>`.

**Step 6 — leave the watchdog running.** It alerts (stdout + stderr, exit
code 1) when a node is down, crash-looping, on a different topic, above the
inode threshold, or when the masterchain tip has not advanced for N seconds —
and it auto-heals only the safe cases.

```sh
scripts/cluster-watchdog.sh --interval 60
```

### 15.3 `preflight` — the fail-closed gate

```sh
scripts/stell-sync.sh preflight
scripts/stell-sync.sh preflight --nodes "A B C D"   # a subset
```

It compares the nodes **against each other** (the real invariant) and against
the expected values in `scripts/cluster-nodes.conf`
(`EXPECT_STELL_SHARDS`, `EXPECT_STELL_ROUND_TIMEOUT_MS`, …). Every difference
is named; the exit code is 1 when there is at least one. Wire it in front of
every deploy:

```sh
scripts/stell-sync.sh preflight || { echo "REFUSING TO DEPLOY" >&2; exit 1; }
```

The values it enforces, and why each one is a NETWORK property rather than a
local preference:

| Parameter | Why it must match |
| --- | --- |
| `STELL_SHARDS` | Decides `registry.is_sharded()`, and therefore the **pubsub topic**. A different value isolates the node. |
| the pubsub topic | The topic is `stellereum/consensus/v1/<epoch>[/shard/<id>]`, with `<epoch>` = the first 8 bytes of the genesis root. Nodes on different topics never exchange a message. |
| the genesis root / epoch | A different genesis root means a different chain. |
| the chain id | Binds every consensus signature and every block hash. |
| `STELL_ROUND_TIMEOUT_MS`, `STELL_DOWN_PROPOSER_TIMEOUT_MS`, `STELL_MIN_BLOCK_MS` | The consensus clock. Different clocks mean different rounds — the same class of split as the topic. |
| `STELL_KEEP_BLOCKS` | The retention window. A node that prunes sooner than its peers stops being able to serve the history. |
| the admission base fee (`STELL_MIN_GAS_LIMIT`) | The mempool admission floor. A different floor means the nodes accept different transactions. |
| the inode usage | A full inode table is a read-only filesystem, and a read-only node drops out of consensus **silently**. |
| the binary path | A binary inside a cargo target dir is deleted by `cargo clean` under the live node. |
| the unit state (`enabled` + `active`) | A disabled unit does not come back after a reboot; an inactive unit is a node that is not voting. |

### 15.4 The orphan-chunk sweeper

```sh
# on the node itself
scripts/node-prune-cron.sh --dir /root/nodeC [--dry-run] [--json]

# systemd (every node!)
cp scripts/systemd/stell-node-prune.service /etc/systemd/system/
cp scripts/systemd/stell-node-prune.timer   /etc/systemd/system/
# edit WorkingDirectory/ExecStart to THIS node's directory
systemctl daemon-reload && systemctl enable --now stell-node-prune.timer
```

How it decides what is garbage:

1. the **referenced set** = every chunk id mentioned by any manifest in
   `<data>/kv.json` (deliberately conservative: an expired manifest's chunks
   count as referenced too);
2. a chunk file is a **candidate** when its name is not in that set **and**
   it is older than the grace period (6 h by default);
3. immediately before the deletion the candidate list is re-verified (a fresh
   `find` of the still-old files + one more pass against the referenced set),
   because chunk ids are content-addressed and a fresh chunk can reuse an id;
4. the deletion itself is batched through `xargs` and capped per run
   (`--max-delete`, default 200 000).

It refuses to run at all when `kv.json` is older than `--max-kv-age` (2 h):
the index it reasons about must be fresh. It also removes the atomic-write
leftovers (`.*.tmp*`) and keeps the two newest `kv.json.bak-*` rotations.

**It never touches** the head pointer's chunks, the active snapshot's
chunks, the store, the keys or the config.

### 15.5 The stale consensus lock

The consensus safety state (height, round, locked block hash) is persisted in
the store under the meta key `consensus`. On restart the node restores it —
and because the rule is "never adopt a peer's round", a node that resumes at
round 56 while its peers are at round 0 **can never rejoin**.

```
scripts/tools/stelops/src/main.rs   # the tool: checkpoint / genesis-root / clear-lock
```

```sh
# build it once (offline, a few seconds — it depends on sled only)
cargo build --release --manifest-path scripts/tools/stelops/Cargo.toml

# read the checkpoint (the node must be STOPPED: sled locks the store)
scripts/tools/stelops/target/release/stelops checkpoint /root/nodeC/data/store
# height=285028 round=379 locked_hash=129c688c… locked_round=376 finalized_height=285027

# the genesis root (= the chain epoch = the topic)
scripts/tools/stelops/target/release/stelops genesis-root /root/nodeC/data/store
# c840d1dc2e6c70eb7c639a193715c0a57375fc78ae1f9749dc3cc73cb4c8ee77
```

### 15.6 The watchdog

```sh
scripts/cluster-watchdog.sh --interval 60 [--once] [--no-heal]
```

| Condition | Auto-heal? | Action |
| --- | --- | --- |
| the service is down / failed | **yes** | `systemctl restart` the unit |
| the inode usage is at the hard threshold | **yes** | run the orphan sweeper on that node |
| a lot of orphan chunks | **yes** | run the orphan sweeper on that node |
| the node is on a different topic | **no** | report only — it is a config error |
| the config drifted (`STELL_SHARDS`, chain id, timeouts, base fee) | **no** | report only |
| the masterchain tip has not advanced for N seconds | **no** | report only — a view-change storm needs a human |
| a stale consensus lock | **no** | report only — use `lockclear --force` |
| the node is behind | **no** | report only — re-syncing is an operator decision |

### 15.7 `doctor` — the single-node diagnosis

```sh
scripts/doctor.sh --dir /root/nodeC --service stell-nodeC.service
scripts/doctor.sh --dir /root/nodeC --service stell-nodeC.service --json
scripts/stell-sync.sh doctor C            # the same, over ssh
```

It reports the config drift against the expected values, the inode usage, the
orphan chunk count, the consensus checkpoint (height / round / lock), the
pubsub topic (expected and subscribed), the binary path + hash, the key
format (**encrypted or plaintext**) and the chain id — as text or as JSON.
