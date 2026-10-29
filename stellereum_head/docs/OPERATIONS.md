# Operating a Stellereum node

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

Two scripts cover both sides. Neither replaces thinking about the genesis
rules in §3 and `testnet/README.md` §0 — they automate the mechanical parts
so there is less room to get those rules wrong.

| side | script | does |
| --- | --- | --- |
| new node (operator) | `scripts/join-network.sh` | generates keys, builds `node.yaml` + env, installs the systemd unit, disk-guard cron and firewall rule, prints the peer-stanza |
| network (admin) | `scripts/add-peer.sh` | appends the stanza to `node.yaml` + `STELL_PEER_PQ_KEYS`, rolling-restarts one unit |

Thin CLI behind it: `stellereum keys init` (generate via the same
`load_or_generate` path `run` uses; idempotent, 0700/0600) and
`stellereum keys peer-stanza` (prints node-id/ed-pub/x-pub/falcon-pub).

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
   without touching anyone's `validators:` or genesis.

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
