# Fresh-genesis runbook

This is the **deliberate new-chain procedure**, not a recovery procedure. It
stops every validator, replaces the binary, wipes only `./data`, founds a new
chain with `STELL_NEW_CHAIN=1`, verifies that every node advances, and then
removes the founding flag.

Tooling:

- `scripts/fresh_genesis.sh` — dry-run by default; `--yes` is required to
  stop, replace, wipe, or start anything.
- `scripts/cluster_liveness.sh` — read-only height / divergence / diagnostics
  check used before and after the run.

> **The one-line rule:** if any validator is still finalizing, or if you cannot
> reproduce the exact genesis inputs (binary, chain id, validator set, faucet
> seed, fork rules), **do not wipe**. See “When NOT to wipe” below.

---

## 1. Preconditions

All of these must be true before the first destructive command.

### 1.1 Decision and blast radius

- [ ] A human has explicitly decided this is a **new chain**, not an incident
      recovery. A fresh genesis destroys history and cannot be rolled back
      after the first finalized block.
- [ ] You have announced the outage window and the new genesis time.
- [ ] No other operator or agent is mid-upgrade, mid-restore, or editing the
      validator configs.
- [ ] The explorer/indexer/faucet owners know their databases will refer to the
      old chain and must be reset or repointed.

### 1.2 Backups and keys

- [ ] `keys/` and `node.yaml` are backed up on every node (they are **kept** by
      the script, but a bad binary or a mistaken `rm` still needs a backup).
- [ ] The `EnvironmentFile` is backed up (it contains node parameters, and may
      contain secrets — store it accordingly, never paste it into a ticket).
- [ ] If you want a forensic copy of the old chain, back up `data/` **before**
      the wipe. It is not a rollback path after finality (see §6).
- [ ] You know the current chain id, fork id, protocol version, genesis root,
      and last finalized height; record them in the incident/change ticket.

### 1.3 Disk and host health

- [ ] Run the script as the user that owns the units: `root` for the system
      units (A/C/D), the node's user for the user unit (B). The script edits the
      `EnvironmentFile` and recreates `data/` with the invoking user's ownership.
- [ ] More than **10 GiB free** on the filesystem holding each node directory.
      `fresh_genesis.sh` refuses below that (override only with a documented
      `--min-free-gb`; the default is the safety margin for the store + WAL).
- [ ] Inodes are not exhausted. On the live layout this was the failure that
      silently dropped Node C out of consensus:
      `df -i /root/nodeA` (and the same for every node).
- [ ] No node is crash-looping on an unrelated problem (bad unit, read-only
      filesystem, missing library). A fresh genesis does not fix those.

### 1.4 Identical network inputs

Every validator must agree on all of these. A difference here means the nodes
will mint different genesis roots, refuse each other's consensus messages, or
split immediately after founding.

| Input | Where to check |
| --- | --- |
| Binary commit / sha256 | `sha256sum <ExecStart binary>` on each node; `/health` `.identity.software` |
| Chain id | `/health` `.identity.chain_id`, `stell_chainId` |
| Fork id / ruleset | `/health` `.identity.fork_id`, `.identity.protocol_major/minor` |
| Genesis root | `stelops doctor <data/store> --text` (pre-wipe record) |
| Validator set | `node.yaml` `validators:` on every node (all members listed) |
| Peer PQ keys | `STELL_PEER_PQ_KEYS` in every env file |
| Faucet seed / dev flags | `STELL_FAUCET_KEY*`, `STELL_DEV_UNSAFE_TESTKEY`, `STELL_LEGACY_GENESIS_ROOT`, `STELL_PURE_PQ` |
| Shards | `STELL_SHARDS` (unset = single-shard canonical testnet) |
| Round/block timings | `STELL_ROUND_TIMEOUT_MS`, `STELL_MIN_BLOCK_MS`, etc. |

The scripts do not compare every value automatically. `fresh_genesis.sh`
checks the binary digest and the node layout; `cluster_liveness.sh` reports the
identity fields from `/health`. The operator must compare the remaining values.

### 1.5 Fork-id / genesis identity check (do this before wiping)

Run on each node, before any wipe:

```bash
# 1) binary identity
sha256sum /root/stellereum/target/release/stellereum   # node A/C/D
sha256sum /home/imm/stellereum-project/multinode/nodeB/stellereum  # node B

# 2) protocol + chain identity (gateway /health, NOT the JSON-RPC port)
curl -sS http://127.0.0.1:8080/health | jq '{
  chain_id: .identity.chain_id,
  fork_id: .identity.fork_id,
  protocol: [.identity.protocol_major, .identity.protocol_minor],
  software: .identity.software.string,
  height: .chain.height.value
}'

# 3) genesis root from the durable store
scripts/tools/stelops/target/release/stelops doctor /root/nodeA/data/store --text | \
  grep -E 'genesis|finalized|snapshot'
```

All four nodes must show the **same** `chain_id`, `fork_id`, protocol pair,
`software.git_hash` (and `dirty=false` for a production run), and the **same
genesis root**. If they do not, stop here: you have a config/identity problem,
not a reason to wipe.

Why this matters:

- `fork_id` is derived from the consensus ruleset. A mixed `fork_id` makes
  nodes refuse participation rather than “auto-negotiate”.
- The genesis root is a pure function of the chain id, validator set, faucet /
  funding inputs, and the derived keys. If it differs, the nodes are not on the
  same chain even before the first block.
- The genesis root is **not** recoverable from the network after a wipe. Record
  the expected value first; verify it again after the fresh boot.

`STELL_NEW_CHAIN` accepts only `1` or case-insensitive `true` for founding
(`stellereum/src/bootstrap.rs`). Use `1` in scripts and units.

---

## 2. The exact sequence

### 2.1 Rehearse first — the default is a dry run

`fresh_genesis.sh` prints every command. Without `--yes` it changes nothing.

```bash
cd /home/imm/stellereum-project

NODES="A=ssh:root@212.113.103.105:/root/nodeA;env=/root/env.A,B=local:/home/imm/stellereum-project/multinode/nodeB;scope=user,C=ssh:root@213.21.246.5:/root/nodeC;env=/root/nodeC/env.C;ssh_opts=-p 2222,D=ssh:root@138.124.102.200:/root/nodeD;env=/root/nodeD/env.D"

scripts/fresh_genesis.sh \
  --nodes "$NODES" \
  --binary /home/imm/stellereum-project/stellereum/target/release/stellereum \
  --timeout 180
```

Read the output and confirm:

1. each node resolves the expected **directory**, **EnvironmentFile**,
   **unit**, **binary path**, and **RPC URL**;
2. the disk check passes on every node;
3. the printed `systemctl stop/start`, `rm -rf …/data`, `STELL_NEW_CHAIN`
   set/remove, and binary-install commands are exactly what you intend.

The `bin=` attribute is only needed when auto-detection is wrong. The live
layout is auto-detected as:

- A/C/D: `<dir>/../stellereum/target/release/stellereum`
- B: `<dir>/stellereum`

### 2.2 Apply

Only after reviewing the dry run:

```bash
scripts/fresh_genesis.sh ...same arguments... --yes
```

What the script does, in order:

1. **Preflight (read-only):** directory, `EnvironmentFile`, unit `LoadState`,
   binary source digest, and `> 10 GiB` free on every node.
2. **Stop** every unit and verify `is-active` is false.
3. **Replace** the binary atomically
   (`install/cat → *.fresh-genesis.tmp → mv -f`), then verify the sha256 on
   every node.
4. **Wipe only** `./data` (`rm -rf <dir>/data && mkdir -p <dir>/data`).
   `keys/`, `node.yaml`, and the env file are untouched.
5. **Set** `STELL_NEW_CHAIN=1` in each `EnvironmentFile` (replacing an existing
   assignment, or appending one line). The original line is remembered.
6. **Start** every unit.
7. **Wait** up to `--timeout` seconds for `stell_blockNumber > 0` on every
   node. It polls the RPC **on the node** (over ssh for remote nodes).
8. **Remove** `STELL_NEW_CHAIN` (restore the original line if one existed).

If any step fails, the script:

- prints the last `--log-lines` lines from each node,
- removes the temporary `STELL_NEW_CHAIN`,
- stops every node (not just the failed one),
- exits `1` and says **ALL NODES LEFT STOPPED**.

That is intentional: a half-started 2-of-4 cluster is worse than a clean stop.

### 2.3 Manual equivalent (if the script cannot be used)

Per node. Substitute the unit scope and paths. Do **not** copy-paste this
against a different node without checking the unit's `ExecStart` and
`EnvironmentFile`.

```bash
# 1. stop
systemctl stop stell-nodeA                 # A/C/D
systemctl --user stop stell-nodeB          # B

# 2. replace binary atomically (A shown; B uses its own path)
install -m 0755 /path/to/new/stellereum /root/stellereum/target/release/stellereum.tmp
mv -f /root/stellereum/target/release/stellereum.tmp /root/stellereum/target/release/stellereum
sha256sum /root/stellereum/target/release/stellereum

# 3. wipe ONLY data (never keys/)
rm -rf /root/nodeA/data
mkdir -p /root/nodeA/data

# 4. temporary founding flag (unit does not inherit your shell!)
echo 'STELL_NEW_CHAIN=1' >> /root/env.A

# 5. start
systemctl start stell-nodeA

# 6. wait for a non-zero height
curl -sS http://127.0.0.1:8545 -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}'

# 7. only after EVERY node is > 0, remove the flag
sed -i '/^STELL_NEW_CHAIN=/d' /root/env.A
```

If the node had an existing `STELL_NEW_CHAIN` line, restore its original value
instead of deleting it. `fresh_genesis.sh` does this automatically.

---

## 3. Verification (all of it, before declaring success)

### 3.1 Heights advancing on every node

```bash
export STELL_RPCS="A=http://127.0.0.1:8545,B=http://127.0.0.1:8546,C=http://127.0.0.1:8545,D=http://127.0.0.1:8545"
export STELL_HEALTH_RPCS="A=http://127.0.0.1:8080,B=http://127.0.0.1:8081,C=http://127.0.0.1:8082,D=http://127.0.0.1:8083"

scripts/cluster_liveness.sh \
  --rpcs "$STELL_RPCS" \
  --health-rpcs "$STELL_HEALTH_RPCS" \
  --interval 2 --window 30 --expected-block-time 1
```

Expected:

- `verdict: OK`, exit `0`;
- every reachable node has a positive `DELTA` and a non-zero `FINALITY`;
- `spread` is `0` or `1`;
- the last line starts `LIVENESS_RESULT=OK`.

The health gateway ports are reachable from the operator box only if you tunnel
them. If not, omit `--health-rpcs`; the RPC still gives height/peer count and
the diagnostics explain that `/health` was unavailable.

A non-zero exit (`1` = STALLED, `2` = DIVERGED) is a hard stop. Read the
diagnostics: verdict reasons, round, last finalized height, peer count, and the
last rejected-proposal reasons. Do not proceed to remove backups or announce
success while this is non-zero.

### 3.2 Same block hash at a common height

Pick the lowest reachable height `H` from the table above, then compare:

```bash
H=1   # replace with the common height from cluster_liveness.sh

for n in A B C D; do
  url=$(printf '%s' "$STELL_RPCS" | tr ',' '\n' | sed -n "s/^${n}=//p")
  printf '%s ' "$n"
  curl -sS "$url" -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"stell_getBlock\",\"params\":[{\"height\":$H}]}" \
    | jq -r '.result.hash // "NO-BLOCK"'
done | tee /tmp/hashes.txt
```

Acceptance: every line has the same hash and none is `NO-BLOCK` / `null`.
Different hashes at the same height are **DIVERGED** even if heights are equal
(`cluster_liveness.sh` catches this too).

### 3.3 `/health` verdict and identity on every node

```bash
for port in 8080 8081 8082 8083; do
  echo "== :$port"
  curl -sS "http://127.0.0.1:$port/health" | jq '{
    verdict: .verdict.status,
    reasons: .verdict.reasons,
    height: .chain.height.value,
    finalized_height: .chain.finalized_height.value,
    round: .consensus.round.value,
    last_finalized_round: .consensus.last_finalized_round.value,
    peers: .p2p.peer_count.value,
    chain_id: .identity.chain_id,
    fork_id: .identity.fork_id,
    software: .identity.software.string
  }'
done
```

Acceptance:

- `verdict` is `ok` on every node (not `degraded` / `critical`);
- `chain_id` and `fork_id` are identical everywhere and match the pre-wipe
  values;
- `finalized_height` is advancing;
- `peers` is non-zero for a multi-validator cluster;
- `software` names the binary you intended to install.

### 3.4 Genesis root identity after boot

Compare the freshly minted genesis root on every node:

```bash
# run on each node (or over ssh); same value everywhere
scripts/tools/stelops/target/release/stelops doctor /root/nodeA/data/store --text | \
  grep -E 'genesis|finalized|snapshot'
```

It must equal the value recorded in §1.5. If it does not, the nodes did not
found the chain you think they did: stop and compare the inputs in §1.4 before
producing blocks you will have to discard.

The RPC `stell_getStateRoot` at the same height is a second, independent
check:

```bash
for n in A B C D; do
  url=$(printf '%s' "$STELL_RPCS" | tr ',' '\n' | sed -n "s/^${n}=//p")
  curl -sS "$url" -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"stell_getStateRoot","params":[]}' \
    | jq -r '.result'
done | sort -u
```

One line = agreement. More than one line = stop.

### 3.5 Confirm the founding flag is gone

```bash
# every node; should print only the original line, if the node had one
grep -n '^STELL_NEW_CHAIN=' /root/env.A /root/nodeC/env.C /root/nodeD/env.D \
     /home/imm/stellereum-project/multinode/nodeB/env.B || true
```

On a normal fresh chain there is **no** `STELL_NEW_CHAIN` line after the run.
If there was one before (for example `=0`), the script restores it exactly.
Never leave `STELL_NEW_CHAIN=1` in a unit's env: the next boot would treat a
dirty/foreign data directory as permission to found again.

---

## 4. Post-run checklist

- [ ] `cluster_liveness.sh` has been `OK` for at least one full window after
      the first finalized block.
- [ ] All four nodes show the same height (within 1) and the same hash at a
      common height.
- [ ] `/health` is `ok` everywhere; no `critical` reasons.
- [ ] Genesis root and fork id match the pre-wipe record.
- [ ] `STELL_NEW_CHAIN` is absent (or restored to its original value).
- [ ] The new genesis root, chain id, fork id, binary sha256, start time, and
      first finalized height are recorded in the change ticket.
- [ ] Explorer/indexer/faucet databases are reset or repointed to the new
      chain.
- [ ] Monitoring and the watchdog are re-enabled.
- [ ] Old `data/` backups are labelled **old chain / forensic only**.

---

## 5. Failure handling

If `fresh_genesis.sh` exits non-zero:

1. It has already printed the last log lines, removed the temporary
   `STELL_NEW_CHAIN`, and stopped every node.
2. Do **not** start individual nodes “to see if they work”. A partial cluster
   can finalize a block on a chain you are about to abandon.
3. Diagnose from the printed logs and `/health` on the stopped unit's last
   journal entries (`journalctl -u stell-nodeX -e`, or `--user` for B).
4. Common causes: binary digest mismatch, wrong `EnvironmentFile` (unit starts
   with the old env), missing keys, different genesis inputs, disk full,
   read-only filesystem, or a unit that is still failed
   (`systemctl reset-failed` after fixing the cause).
5. Rerun the **dry run** first, then `--yes`. The script is safe to rerun: it
   stops, replaces, wipes, and restores the flag again.

---

## 6. Rollback limits

| Point in time | What is possible |
| --- | --- |
| Before any destructive command | Abort. Nothing changed. |
| After stop, before first new block | Stop, restore the backed-up `data/` and the old binary, start, verify old genesis root. This is a restore, not a rollback of a live chain. |
| After the first **finalized** block | **No rollback.** The new chain is canonical. The old data is a different chain; restoring it on one node makes that node unable to validate the new chain. |
| After finality, one node broken | Forward-fix that node, or sync it from the new chain. Do not restore its old data dir. |
| After finality, whole chain unwanted | Only another coordinated fresh genesis (all nodes, new chain id / announced genesis), never a per-node rollback. |

Consequences to state explicitly in the change ticket:

- Finality is irreversible here. There is no “undo” once a quorum certificate
  exists on the new chain.
- A per-node restore after finality is a **fork/downtime**, not a rollback.
- Keys survive a wipe; chain history does not. Backups of the old `data/` are
  forensic artifacts, not a recovery path for the new chain.

---

## 7. When NOT to wipe

A fresh genesis is the most destructive tool in the runbook. Do not use it for
any of these:

1. **One validator is down and quorum is alive.** Restart/repair that unit.
   The remaining validators are still finalizing; a wipe turns a degraded
   cluster into a new chain.
2. **A node is behind but within the snapshot window.** Let snapshot-sync /
   catch-up run. Check `tip − newest_snapshot ≤ 256` before deciding.
3. **Disk or inodes are full.** Prune orphan chunks (`node-prune-cron.sh`),
   clean build artifacts, and free space. Wiping loses history without fixing
   the filesystem.
4. **Config drift** (wrong `STELL_SHARDS`, chain id, peer keys, unit/env file).
   Fix the config and restart. `stell-sync.sh preflight` names the difference.
5. **Mixed binary / wrong fork id.** Install the matching binary and restart.
   A wipe does not make incompatible consensus rules compatible.
6. **A stale consensus lock.** Use `stell-sync.sh lockclear <node> --force`.
7. **Execution divergence** (same height/hash, different state root). Find the
   minority with `stelops diverge`; do not wipe the majority or the last
   healthy node.
8. **A halted chain with recoverable data.** If a backup exists, or
   `H − B ≤ 256`, restore/sync one node per `docs/UPGRADE_AND_RECOVERY.md`
   §3.3. Do not wipe the remaining data dirs.
9. **You cannot reproduce the exact genesis inputs** (keys, faucet seed,
   validator set, fork rules). Wiping would create a chain nobody else can
   join, or a chain that diverges from the explorer/indexer expectations.
10. **Any node is still finalizing.** A wipe is a chain-level decision, not an
    incident reflex. Get explicit human sign-off first.

If in doubt: run `scripts/cluster_liveness.sh` and
`scripts/stell-sync.sh preflight` first. They are read-only, and they answer
“is this a liveness problem, an identity problem, or actually a decision to
start over?”
