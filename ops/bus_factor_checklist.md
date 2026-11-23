# Bus-factor checklist (second operator)

The cluster currently has one operator. This is the minimum a second person
needs in order to act without asking, and the drills that prove they can. No
secret material belongs in this file.

## 1. Access inventory (who can reach what)

| Asset | Where | Access model |
|---|---|---|
| nodeA | `212.113.103.105`, `/root/nodeA` | root SSH key |
| nodeD | `138.124.102.200`, `/root/nodeD` | root SSH key |
| nodeC | `213.21.246.5:2222`, `/root/nodeC` | root SSH key |
| nodeB | this host, `multinode/nodeB` | local user `imm`, systemd `--user` |
| public RPC | Cloudflare → `rpc.stellereum.org` | provider account |
| DNS seeds | `seeds.stellereum.org` TXT | DNS provider account |
| docs / site | `docs.stellereum.org`, `stellereum.org` | `scripts/deploy-docs-site.sh` from this host |
| repo | `github.com/stellereum/stellereum` | org membership, PAT for pushes |
| faucet | `/api/faucet-public` | `STELL_FAUCET_TOKEN` in the node env |
| cold withdrawal keys | one per validator (`keys/withdrawal.key` on its node) | needed for `validator unjail` |

Second operator needs: SSH to all four hosts, GitHub org write, DNS/provider
read, and a documented (not shared-password) path to the cold keys.

## 2. Drills (run quarterly, record the date + who ran it)

1. **Read-only triage**: `scripts/doctor.sh`, `./scripts/observe-local.sh --check`,
   and the Grafana dashboard; say out loud what is wrong from the numbers alone.
2. **Rolling deploy**: `rolling-deploy.sh stage <bin> --nodes "A B C D"`, then
   `activate --nodes "C"` on one node only; confirm `4/4` and no jail. Abort
   afterwards (do not complete the rollout during a drill).
3. **Jail recovery**: pick a jailed validator, run `validator unjail` with the
   cold key at or after `release_height`, confirm it re-enters the set.
4. **Safety quarantine**: follow `ops/safety_recovery_runbook.md` on a spare
   store copy — `safety-reset` then `safety-init` — and confirm the node starts
   without `QUARANTINED`.
5. **Snapshot restore**: restore the public snapshot into a scratch directory
   and start an observer on it; confirm it reaches the tip.
6. **Backup**: `scripts/backup_offhost.sh` then `scripts/backup_verify.sh`;
   record the restore time in `ops/backup_runbook.md`.

## 3. Rules the second operator must know

- **Never restart a set member while the set is below 4/4**: at 3/4 the quorum
  is 3/3, at 2/4 it is 2/2 — one more restart halts the chain.
- **No heavy builds while the set is below 4/4** (nodeB shares this host; a
  starved validator jails after 42 misses = 16.8 s at the 400 ms floor).
- Pause `stell-node-guard.timer` around any stop/start; otherwise it starts a
  second instance on the same store and corrupts `safety_record_v1`.
- Watch `df -i`, not only `df -h`: the chunk store exhausted inodes with 1.5 GB
  of disk still free.
- The ready endpoint is not trustworthy yet (`P0-READINESS-DEAD`): use
  `stell_consensus_height` advancing and `stell_validator_efficiency_ratio`
  instead of `/readyz`.

## 4. Current single-operator risks (mitigations tracked)

| Risk | Mitigation now | Real fix |
|---|---|---|
| One person holds every key and login | this checklist + quarterly drills | second operator with independent credentials |
| Cold keys live next to the validator | documented, used only for unjail | remote signer + 4-eyes (Wave 2) |
| All three remote nodes on one provider (AS210644, Helsinki) | snapshot restore + public fallback | second provider / region (Wave 1 P0-1) |
