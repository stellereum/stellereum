---
title: Run an observer
description: Join the testnet as a full non-validating observer — snapshot bootstrap, ports and verification.
outline: deep
---

# Run an observer node

An **observer** is a full node that follows the chain, serves RPC, and replays
every block it adopts — but never proposes or votes. It holds **no stake** and
needs **no validator key**.

Observers are the right default for:

- wallets, exchanges and indexers that need their own trustworthy RPC;
- a validator operator's first sync, before registration;
- monitoring and incident response;
- anyone who wants to verify the chain without economic exposure.

::: tip Observer is also the safe first phase of a validator
`scripts/join-testnet.sh --mode validator` still starts the node with
`STELL_OBSERVER=1`. You promote it only after registering on-chain and entering
the active set. A fresh key that starts as a validator mints its own genesis
and splits silently.
:::

## Hardware

| Role | vCPU | RAM | Disk |
| --- | --- | --- | --- |
| observer / follower | **≥ 2** | **≥ 4 GB** | **≥ 60 GB SSD** |

An observer replays every block, so a spinning disk stalls the persist queue
and shows up as consensus lag even though the node never votes. **1 vCPU is
explicitly insufficient** in the project's live measurements, even for
following; it is certainly insufficient for a validator.

## One-command join

From the repository root:

```bash
scripts/join-testnet.sh --mode observer \
  --home "$HOME/stell-observer" \
  --name observer-$(hostname -s) \
  --listen 0.0.0.0:9411 \
  --advertise <PUBLIC_IP>:9411 \
  --rpc 127.0.0.1:8545 \
  --explorer 127.0.0.1:8080 \
  --non-interactive
```

Useful flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--mode observer` | interactive prompt | observer role |
| `--home DIR` | `$HOME/stell-observer` | node home |
| `--name NAME` | `observer-<host>` | name in `node.yaml` |
| `--listen ADDR:PORT` | `0.0.0.0:9411` | P2P QUIC listen address |
| `--advertise IP:PORT` | detected IP, else unset | public P2P address |
| `--rpc ADDR:PORT` | `127.0.0.1:8545` | JSON-RPC listen |
| `--explorer ADDR:PORT` | `127.0.0.1:8080` | gateway/explorer listen |
| `--seeds DOMAINS` | `seeds.stellereum.org` | `STELL_DNS_SEEDS` |
| `--peers-file FILE` | built-in live peers | custom peer list |
| `--snapshot-url URL` | `https://rpc.stellereum.org/snapshot/latest.tar.zst` | snapshot archive |
| `--skip-snapshot` | off | start from genesis instead |
| `--binary PATH` | auto-detect | `stellereum` binary |
| `--chain-id ID` | `5757` | target chain |
| `--start` | off | start immediately |
| `--force` | off | overwrite `node.yaml` / `node.env` (keys preserved) |

What the script does, in order:

1. creates `$HOME/stell-observer/{keys,data}` at mode `0700`;
2. mints a keystore passphrase and exports `STELL_KEY_PASSPHRASE`;
3. runs `stellereum keys init --keys-dir …/keys` (encrypted at rest,
   idempotent — existing keys are never overwritten);
4. writes `node.yaml` from the template with the peer list and DNS seeds;
5. writes `node.env` at mode `0600`:

   ```bash
   STELL_OBSERVER=1
   STELL_SHARDS=0
   STELL_CHAIN_ID=5757
   STELL_RPC_LISTEN=127.0.0.1:8545
   STELL_EXPLORER_LISTEN=127.0.0.1:8080
   STELL_ARCHIVE=0
   STELL_KEEP_BLOCKS=8000
   STELL_DNS_SEEDS=seeds.stellereum.org
   STELL_BROADCAST_JOIN_MS=300
   STELL_KEY_PASSPHRASE=<minted secret>
   ```

6. downloads and extracts the snapshot into `data/store` (unless it already
   exists or `--skip-snapshot` was passed):

   ```bash
   curl -fsSL "$SNAPSHOT_URL" | tar -I 'zstd -d' -xf - -C "$HOME/stell-observer/data/"
   ```

7. prints the exact start command and verification commands.

::: warning Back up `keys/` and `node.env` together
`node.env` carries the passphrase for the encrypted keys. A backup of `keys/`
without `node.env` is unreadable; a backup of `node.env` without `keys/` is
useless. Both are `0600`/`0700` secrets.
:::

## Manual snapshot bootstrap

If you do not use the script, the supported flow is still **snapshot first**,
never copy another node's `./data` over ssh:

```bash
mkdir -p ~/stell-observer/data
curl -fsSL https://rpc.stellereum.org/snapshot/latest.tar.zst \
  | tar -I 'zstd -d' -xf - -C ~/stell-observer/data/

test -d ~/stell-observer/data/store || {
  echo "snapshot did not create data/store" >&2; exit 1;
}
```

Then initialize keys and the environment:

```bash
export STELL_NODE_PASSPHRASE='<long random passphrase>'
stellereum keys init --keys-dir ~/stell-observer/keys
```

```bash
cd ~/stell-observer
set -a; . ./node.env; set +a
stellereum node-bootstrap --config node.yaml --shard 0
```

`node-bootstrap` is a **fail-closed** preflight, then the live sync engine:

1. clean data dir;
2. `STELL_OBSERVER=1`;
3. faucet key configured (the network's shared genesis faucet key);
4. a live peer pointer;
5. a non-empty `validators:` list.

After the gate it runs snapshot-sync (state **and every committed domain**,
root-checked before commit), a short body walk, then live follow. Expected log
sequence:

```text
[bootstrap] stage 1/4: preflight OK ...
[bootstrap] stage ...
[sync] caught up N blocks to height M
```

::: danger Never join by copying `./data`
A foreign store carries a foreign genesis fingerprint. The node either refuses
to start (`genesis state root mismatch`) or, worse, follows a private chain
while looking healthy. Use the snapshot or `node-bootstrap`.
:::

## Start

```bash
cd ~/stell-observer
set -a; source node.env; set +a
stellereum run --config node.yaml --shard 0 --parallel-exec
```

`--parallel-exec` enables disjoint-wave parallel block execution. It is the
normal flag for both observers and validators.

## Ports

| Port | Protocol | Purpose | Exposure |
| --- | --- | --- | --- |
| `9411/udp` | QUIC | observer P2P (validator default is `9410/udp`) | inbound from peers |
| `8545/tcp` | HTTP | JSON-RPC (`STELL_RPC_LISTEN`) | **loopback by default** |
| `8080/tcp` | HTTP | gateway/explorer, `/healthz`, `/readyz`, `/metrics` | **loopback by default** |
| `8088/tcp` | HTTP | indexer (separate process) | loopback / private |
| configured | UDP | infnode `metrics-listen` (optional) | private |

Open only the P2P UDP port inbound:

```bash
sudo ufw allow 9411/udp
# or
sudo iptables -A INPUT -p udp --dport 9411 -j ACCEPT
```

Do **not** expose `8545` or `8080` to the internet without a reverse proxy that
adds authentication. The in-process rate limiter is a speed bump, not access
control.

## Verify it follows the chain

```bash
RPC=http://127.0.0.1:8545
rpc() { curl -s -X POST "$RPC" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-\{\}}}"; }

rpc stell_syncing        # true while a verified peer is ahead
rpc stell_blockNumber    # must JUMP toward the peers, not sit
rpc stell_getStateRoot   # must equal a live peer's root at the same height
rpc stell_getValidators  # same validators / total_power / quorum as peers
```

The decisive check is **same height, same root**:

- same height + same root → one chain;
- same height + different root → **stop, do not transact**. Diff
  `STELL_FAUCET_KEY` (by sha256) and the `validators:` lists. The node is on a
  different genesis.
- lower height + same root → normal catch-up.

An observer reporting an empty or zero-power validator set never enters the
consensus loop; it is not following the network.

## What an observer does and does not do

| Does | Does not |
| --- | --- |
| downloads and verifies snapshots | propose blocks |
| replays every adopted block | vote in consensus |
| serves RPC/gateway reads | earn rewards |
| gossips transactions | hold stake or a validator key |
| exposes `/readyz` and `/metrics` | require `STELL_FAUCET_KEY` for consensus (but bootstrap needs it for the genesis fingerprint) |

`STELL_OBSERVER=1` is a hard role switch: the node runs RPC, sync and
follow, but no propose/vote path.

## Operating notes

- **Disk grows.** The join script sets `STELL_ARCHIVE=0` and
  `STELL_KEEP_BLOCKS=8000`, a bounded starting point. Keep the same values on
  every node you operate; retention is node-local, so a mismatch does not split
  the chain, but it changes what history you can serve.
- **Watch inodes, not just bytes.** Orphan chunk files have filled a node's
  inode table and silently dropped it out of consensus while RPC stayed up.
  Run the sweeper timer on **every** node. See
  [Operations](/nodes/operations#inode-and-disk-guards).
- **Keep the binary outside a cargo target dir.** `cargo clean` under a live
  node produced `203/EXEC` crash loops.
- **Do not run two processes on one store.** sled holds an exclusive lock.
  A second process exits with `Could not acquire lock`; wait ~20 s and verify
  `pgrep -f "stellereum run"` is empty before restarting.

## Promote to validator

Only after the observer is fully synced and its state root matches a peer:

1. fund the cold withdrawal address on the masterchain (`-1:<hex>`) with at
   least 1,100 STELL;
2. register on-chain with `stellereum validator register-validator`;
3. set `STELL_OBSERVER=0` and restart.

See [Run a validator](/nodes/validator).

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `genesis state root mismatch` | wrong faucet key, validator list or binary | restore the network's config; do not wipe blindly |
| snapshot extraction creates no `data/store` | truncated download or wrong archive | re-download; check free space |
| `stell_syncing` stays true forever | no verified peer sighting / wrong topic | check `STELL_SHARDS`, DNS seeds, UDP `9411` |
| height flat, `stell_syncing` false | stalled network or isolated node | compare roots with a peer; check [Monitoring](/nodes/monitoring) |
| RPC works, node silently out of consensus | full inode table | `df -i`; run the sweeper |
| `Could not acquire lock` | old process or stale lock | kill, wait, verify, restart |

## Next

Once the observer reports the same root as a peer, [Run a validator](/nodes/validator) covers registration and promotion. [Operations](/nodes/operations) covers the disk and inode guards that keep an observer healthy.
