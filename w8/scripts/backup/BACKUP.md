# Stellereum node backup & restore

Units: `scripts/systemd/stell-nodeA.service`, `scripts/systemd/stell-nodeB.service`
(install copies on the server: `/etc/systemd/system/stell-nodeA.service`,
`/etc/systemd/system/stell-nodeB.service`, then `systemctl daemon-reload`).
Scripts here: `backup.sh`, `restore.sh`. Nothing here is ever enabled or
started automatically — the operator does that by hand (see below).

## What is backed up

Per node, one tarball (`stell-node<A|B>-<UTC-timestamp>.tar.gz`), members
relative to `/root`, permissions preserved (`tar -p`):

| tarball member       | live path            | why it matters                                        |
|----------------------|----------------------|-------------------------------------------------------|
| `nodeA/node.yaml`    | `/root/nodeA/node.yaml` | peer set, listen/advertise addrs — defines the chain |
| `nodeA/data/`        | `/root/nodeA/data/`     | sled store (`store/db` + snapshots), kv/dht/routes/subs JSON |
| `nodeA/keys/`        | `/root/nodeA/keys/`     | `identity.key`, `e2e.key` (mode 600, dir 700)         |
| `env.A`              | `/root/env.A`           | `STELL_RPC_LISTEN`, `STELL_RPC_AUTH_TOKEN`, faucet vars (mode 600) |

(Same table with `B` for node B.) Only file **names** are ever echoed; secret
**values** are never printed, sourced, or logged by these scripts.

## Where & retention

- Destination: `--dir DIR`, else `$BACKUP_DIR`, else `/root/backups/`.
- Tarballs are written mode `600` — they contain key material and env secrets.
  Never commit them, never copy them off-host in the clear.
- Retention: `--keep N`, else `$BACKUP_KEEP`, else **7**. After each successful,
  verified backup, only the N newest `stell-node<A|B>-*.tar.gz` per node are
  kept; older ones are deleted.
- Every tarball is verified immediately after writing (`tar -tzf` must list,
  and all four members above must be present) before pruning runs.

## Backing up

```sh
# both nodes (default keeps 7 each)
scripts/backup/backup.sh
# one node, custom destination/retention
scripts/backup/backup.sh --node A --dir /root/backups --keep 14
```

For a restore you can trust, stop the node first — a tarball taken while the
node runs can catch the sled store mid-write:

```sh
systemctl stop stell-nodeA   # resp. stell-nodeB
scripts/backup/backup.sh --node A
systemctl start stell-nodeA
```

`backup.sh` warns (never fails) when the unit is active or a `stellereum run`
process still has the node dir as its cwd.

## Exact restore procedure

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

What `restore.sh` does, in order:

1. `systemctl stop stell-node<A|B>` (when the unit exists) and waits for
   inactive. Then scans `/proc`: any `stellereum run` process whose cwd is
   still `/root/node<A|B>` means the sled lock on `./data/store/db` is (or may
   be) held → **refuse with an error, exit 1**. It will never `kill -9` a
   running node and restore over it; a SIGKILLed sled writer is exactly how you
   get a torn store.
2. Rejects archives that are not verifiably a backup of *that* node (member
   check via `tar -tzf`).
3. Snapshots the *current* state to
   `/root/backups/pre-restore-node<A|B>-<ts>.tar.gz` so a bad restore is
   reversible. If the snapshot fails, the restore aborts.
4. Extracts over `/root`, re-enforces `700` on `keys/` and `600` on key files
   and the env file.
5. Prints the `systemctl start` + `journalctl` commands and stops. You start it.

## Fingerprint mismatch: what it means and what to do

If after a restore the node exits with:

```text
genesis state root mismatch for this data directory:
  stored: <hex>
  config: <hex>
This node was previously run with different genesis parameters (validator set,
balances, or STELL_FAUCET_KEY). Continuing would put it on a different chain.
Wipe ./data to start a new chain, or restore the original configuration.
```

that is the node's own genesis-fingerprint check (`src/main.rs`, stored as
`genesis_state_root` in the sled metadata) **refusing to run old data on a new
chain — a safety net, not a bug**. Your backup predates a genesis change
(validator set edited in `node.yaml`, faucet key / balances changed in env).

Do:

- If the genesis change was intended and all nodes moved: this backup is
  obsolete for the live chain. Either restore a backup taken *after* the
  change, or wipe and rejoin fresh:
  `systemctl stop stell-nodeA stell-nodeB`, delete `/root/nodeA/data`
  (and B), `systemctl start ...`. A new genesis root means **every** node must
  be wiped — mixed old/new data dirs never agree.
- If the genesis change was accidental: put back the original `node.yaml` /
  env (the tarball contains both: `tar -xzOf <archive> nodeA/node.yaml`,
  `env.A`) and start again.
- Never "fix" it by deleting just the metadata key or hand-editing the store.

## Deliberately not covered

- No auto-start after restore (operator verifies first).
- No `kill -9` path anywhere near the sled lock.
- No backup encryption at rest beyond filesystem modes — add age/sops if
  tarballs ever leave the host.
- Logs are not backed up (they live in the journal now) and were never needed
  for a restore.
