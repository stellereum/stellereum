# Off-host backup runbook (3-2-1 for chain data)

Scope: local-cluster / multinode node operators. All commands are
non-destructive: live dirs are only ever READ (`cp -a` out, never
move/rm/write). Verification reuses `scripts/backup_verify.sh`.

## 1. 3-2-1 policy adapted to chain data

- **3 copies**: (1) live data dir, (2) on-host staged image under
  `tmp/backup-offhost/backup-<TS>/`, (3) one off-host copy of the
  `*.tar.gz.enc` artifact (+ its `.sha256`).
- **2 media**: local disk (staged image) + off-host destination (local
  removable dir today; remote URIs are REFUSED by the script until an
  uploader is configured — fail closed).
- **1 off-site**: the encrypted artifact copied via the upload hook
  (`--upload-target` + explicit `--confirm-live`).

## 2. What is backed up (and what is NOT)

| Item | Source | How |
|---|---|---|
| Chain data | `run/cluster/node<i>/data` (or any `--data-dir`) | `cp -a` copy, read-only |
| Node config | `run/cluster/node<i>/node.yaml` (auto-found next to data dir, or `--node-yaml`) | `cp -p` copy |
| Keys | `../keys` adjacent dir | **INVENTORY ONLY** (`keys.inventory`: file names + modes). Key *contents* are NEVER copied, encrypted, or uploaded |
| Integrity | staged image | `manifest.sha256` (sorted `sha256sum`), then `tar.gz` + encrypt |

Encryption (checked 2026-11-02): `age` preferred when installed, else
`openssl enc -aes-256-cbc -pbkdf2 -iter 200000` (active backend on this
host: OpenSSL 3.6.2, `age` absent). Passphrase via `--passphrase-file`
(chmod 600), never on the command line.

## 3. Cadence

- **Pre-upgrade**: before any binary swap (cf. `ops/upgrade_rehearsal.md`).
- **Scheduled**: daily for validating nodes, weekly for observers (adapt to
  chain growth; retention `--keep` default 5 images).
- **On demand**: before `down`/`reset` or any destructive cluster command.

Crash-consistency note (same as `backup_verify.sh`): a `cp -a` of a LIVE
node is a filesystem copy, not a consensus snapshot. For a strict backup,
stop the node first (`./scripts/local-cluster.sh stop <i>`), then back up.

## 4. Commands

Dry-run first (changes nothing, touches nothing):

```bash
scripts/backup_verify.sh --data-dir run/cluster/node1/data --dry-run
scripts/backup_offhost.sh --data-dir run/cluster/node1/data --dry-run
scripts/backup_restore_drill.sh --backup-dir tmp/backup-offhost/backup-<TS> --dry-run
```

Real backup (writes only under `--out-dir`, default `tmp/backup-offhost`):

```bash
scripts/backup_offhost.sh --data-dir run/cluster/node1/data \
  --passphrase-file /path/to/backup.pass --keep 5
```

Copy off-host (local dir target; STILL copies nothing without the flag):

```bash
scripts/backup_offhost.sh --data-dir run/cluster/node1/data \
  --passphrase-file /path/to/backup.pass \
  --upload-target /mnt/offhost/stell-backups --confirm-live
```

Without `--confirm-live`, any `--upload-target` is REFUSED (exit 2) and
nothing is copied. `s3://`, `host:path`, and any URI target are always
refused — copy the `.enc` manually until an uploader is configured.

## 5. Restore drill (quarterly, and after every tooling change)

Into a TEMP dir only — never over a live path:

```bash
scripts/backup_restore_drill.sh --backup-dir tmp/backup-offhost/backup-<TS> \
  --passphrase-file /path/to/backup.pass
```

The drill: (1) decrypts to temp, (2) unpacks to temp, (3) `sha256sum -c`
the shipped manifest, (4) calls `scripts/backup_verify.sh --data-dir`
on the restored copy for the boot-read check (store markers + JSON parse).
Drill passes only if ALL steps pass. Direct verify of any data dir:

```bash
scripts/backup_verify.sh --data-dir <path> [--keep-work-dir]
```

## 6. Forbidden

- Writing into, moving, or deleting live `data/`/`keys/` dirs.
- Including key *contents* in any image (inventory only — audit with
  `grep -r` for key material before off-hosting).
- Real uploads without `--confirm-live`; any remote-URI upload.
- `todo!`/dummy content in these scripts: every step must execute.
