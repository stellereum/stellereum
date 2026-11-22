# Validator onboarding runbook (end to end)

One key, from zero to proposing, claiming, and leaving — with the exact
command for every step and what success looks like. Every command below
was verified to exist in this tree; every number is grepped from code
(the source is named per step so you can re-check it).

Notation: `$RPC` is your node's JSON-RPC endpoint
(default `http://127.0.0.1:8545`).

```sh
rpc() { curl -s -X POST "$RPC" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-\{\}}}"; }
```

> New here? For standing a node up at all, see
> [`../testnet/README.md`](../testnet/README.md); for what will page you at
> 3am, see [`OPERATIONS.md`](OPERATIONS.md) (this runbook cross-links it
> per step). Thin CLI reference: `stellereum --help`.

---

## 0. What you are signing up for

- **Bond floor:** `MIN_VALIDATOR_BOND` = **1000 STELL** plus the admission
  buffer `STELL_MIN_BOND_BUFFER` = **100 STELL**
  (`src/staking.rs:45`, `:58`), i.e. **a new bond needs 1100 STELL of
  self-bond** (`required_bond_floor_nano`, `src/staking.rs:62`). A bare
  1000-STELL bond is refused at admission — this is the "1000+100 STELL
  floor".
- **Election is automatic, top-250:** `StakingLedger::to_validator_set`
  sorts by total stake (descending, id tiebreak) and truncates to
  `MAX_ACTIVE_VALIDATORS` = **250** (`src/staking.rs:1315-1330`, `:176`).
  There is no application transaction and no manual election step: bond
  enough stake and the runtime re-derives the set at the height boundary
  (`refresh_validator_set_from_staking`, see `OPERATIONS.md` §10
  "Becoming a validator"). Below the top 250 you are bonded but **not
  proposing**.
- **Quorum math decides liveness:** `quorum_power() = floor(2·total/3)+1`
  (`OPERATIONS.md` §5). With 2–3 equal-stake validators **every** validator
  must sign; run four or more before you depend on the chain.
- **Commission is set at bond time and changeable in Ruleset v7** — the
  wallet `stake` command takes `--commission-bps N` (0–10000) for a NEW
  validator and the governance default (1000 bps = 10 %,
  `DEFAULT_COMMISSION_BPS`, `src/staking.rs:232`) when omitted; a top-up
  keeps the registered rate. Thereafter `stellereum validator
  announce-commission` → `apply-commission` (OpCodes 63/64) changes it after
  a 30,000-height delay, at most 500 bps per step, with a 30,000-height
  cooldown. See §7 and `RPC.md` §5.

Hardware before you start: 1 vCPU is **explicitly insufficient** for a
validator (scheduler starvation measured live). See `OPERATIONS.md` §1
"Sizing" for the minimum table. Do not onboard a validator onto a host
that fails that table.

---

## 1. Generate node keys — `stellereum keys init`

```sh
stellereum keys init --keys-dir ./keys
```

Uses the same `load_or_generate` path as `run` (idempotent: existing keys
are loaded, never overwritten; `src/main.rs`, `Keys::Init`). Expected
output: the `NODE IDENTITY` line. Permissions after the run: dir `0700`,
key files `0600` (`OPERATIONS.md` §10).

Fail-closed: without a passphrase in the environment the node refuses to
write keys unencrypted (`OPERATIONS.md` §14.2). Set **one** of
`STELL_NODE_PASSPHRASE` / `STELL_KEY_PASSPHRASE` /
`INFNODE_KEY_PASSPHRASE` (first non-empty wins).

Validator signing is **FULL-PQ**: the cold withdrawal key and the hot voting
key are both Falcon-512. There is no Ed25519 key path for validator signing.

## 2. Print the peer stanza — `stellereum keys peer-stanza`

```sh
stellereum keys peer-stanza --keys-dir ./keys --name node-e
```

Prints `node-id` / `ed-pub` / `x-pub` / `falcon-pub` (public keys only —
this is the one file you send to the network admin; `src/main.rs`,
`Keys::PeerStanza`). If you rotate the Falcon key later
(`keys rotate-falcon --force`), the validator address **changes** and you
must re-stake under the new address (`OPERATIONS.md` §10–§11.1).

## 3. Join the network — `scripts/join-testnet.sh`

```sh
scripts/join-testnet.sh --mode validator \
  --advertise <PUBLIC_IP:9410> \
  --peers-file <admin-supplied-current-set.yaml>
```

What it does (`OPERATIONS.md` §10, Step 1): `keys init` for the node identity
and hot Falcon-512 voting key, a second `keys init --falcon-file` for the cold
withdrawal key, saves + prints the peer-stanza (`peer-stanza.txt`), writes
`node.yaml` (peers copied from `--peers-file`; `validators:` empty), writes
`node.env` (mode 600) with `STELL_OBSERVER=1`, downloads the snapshot, and
prints the next steps. It does **not** install a systemd unit or firewall rule
— do that from the printed steps and `OPERATIONS.md` §10. Pass
`--skip-snapshot` if you intend to run the `node-bootstrap` gate in §4 (it
requires a clean data dir).

**New nodes always start as observers** (`STELL_OBSERVER=1`): a fresh key
must follow the chain, not mint its own genesis. Inputs that must be right:
`--peers-file` the network's **current** validator set, `--advertise`
diallable, and — if this node runs the faucet — `STELL_FAUCET_KEY` in
`node.env` byte-identical to the network (else a private genesis + silent
split, `OPERATIONS.md` §3).

## 4. First start through the bootstrap gate — `node-bootstrap`

```sh
cd ~/stellereum-node && set -a; . ./node.env; set +a
stellereum node-bootstrap --config node.yaml --shard 1
```

Fail-closed preflight (clean data dir, `STELL_OBSERVER=1`, faucet key set,
live peer pointer, non-empty `validators:`), then snapshot-sync (state +
**every** committed domain incl. the staking ledger, root-checked before
commit), then a short body walk, then live follow
(`OPERATIONS.md` §10, Step 2.5; `src/main.rs`, `NodeBootstrap`).

Expected log lines in order:

```
[bootstrap] stage 1/4: preflight OK ...
[bootstrap] stage ...            # snapshot-sync with per-height QC proofs
[sync] caught up N blocks to height M
```

## 5. Confirm it follows the chain

```sh
rpc stell_syncing                  # true while a verified peer is ahead
rpc stell_blockNumber              # must JUMP toward the peers, not sit
rpc stell_getStateRoot             # must equal a live peer's root at same height
rpc stell_getValidators            # same validators / total_power / quorum as peers
```

Same roots at equal heights = one chain. Same height + different root =
**stop, do not transact** — diff `STELL_FAUCET_KEY` (by sha256) and the
`validators:` lists (`OPERATIONS.md` §3 triage, §10 Step 3). A newcomer
reporting an empty/zero-power set never enters the consensus loop
(`OPERATIONS.md` §4).

## 6. Fund the account — faucet drip (fees only; it cannot fund the bond)

```sh
rpc stell_faucet '{"address":"-1:<YOUR-64-HEX>"}'
```

- Method: `stell_faucet` (`src/rpc.rs:4092`). Gated by `STELL_FAUCET_TOKEN`
  (fail-closed) + 20 requests/hour/IP + **50 STELL lifetime cap per address**,
  enforced on every faucet path.
- Default token-authenticated drip **2 STELL** (`Faucet::default_drip_nano`;
  `STELL_FAUCET_DRIP_STELL` overrides it, whole STELL); `amount` is clamped
  down to the drip, then to the cap remainder (`RPC.md` §4). The public
  (tokenless) `POST /api/faucet-public/:address` path also drips **2 STELL**
  (`STELL_PUBLIC_DRIP_NANO`) under a **45-minute per-address cooldown**.
- **The faucet cannot fund a validator.** 50 STELL is the lifetime ceiling;
  a new bond needs **1,100 STELL** (1,000 STELL minimum + 100 STELL buffer).
  Validator stake is provisioned by the Foundation on request, or by an
  operator transfer. Raising the cap means setting
  `STELL_FAUCET_LIFETIME_CAP_STELL` and restarting with the network's
  agreement.
- Success shape: `{"credited_nano":"…","recipient":"…","tx_hash":"…","shard":…}`.
- **Fund the masterchain form** (`-1:<hex>`) for gas: staking bonds on the
  masterchain, and a bare-address drip executes on the workchain where a
  bond can never be read. On a sharded node the faucet serves **only its own
  shard's** recipients (`RPC.md` §4).
- The drip is an ordinary mempool transfer, not a balance write: watch
  `tx_hash` via `stell_getTransactionStatus` until `success`
  (`RPC.md` §4). Errors: `-32601` faucet disabled; `-32000` cap reached or
  cross-shard refusal (burns **no** nonce, no cap).

## 7. Bond stake — `stell-wallet stake` (alias: `bond`)

```sh
stell-wallet stake --validator <YOUR-64-HEX> 1100
# dry run first:
stell-wallet stake --validator <YOUR-64-HEX> 1100 --dry-run
```

- Builds `SysCallStake { validator, amount }`
  (`stell-wallet/src/main.rs:1431`, `:1458`). `--validator` defaults to
  your own key (self-bond = register as validator).
- Floor: **1100 STELL** (1000 + 100 buffer, §0). Below the governed minimum
  the block reverts with `stake below the governed minimum`
  (`src/svm.rs:1745-1785`); below the ledger floor, `BondBelowMinimum`.
- On top-up of an existing validator the same opcode just adds bond
  (`ledger.add_bond`).
- **Commission at registration** comes from `--commission-bps N` on the
  wallet `stake` command when given, else from governance
  (`ctx.default_commission_bps`, default 1000 bps, `src/staking.rs:232`)
  — the plain `SysCallStake` opcode carries **no** commission field
  (E1b added `SysCallStakeWithCommission` for the explicit rate).
  In Ruleset v7 it is **changeable afterwards** via `announce-commission` →
  `apply-commission` (30,000-height delay, max 500 bps per step,
  30,000-height cooldown).
- The **1,100 STELL must already be on the masterchain**, provisioned by the
  Foundation on request or an operator transfer; the faucet cannot supply it
  (§6).

Verify: `rpc stell_stakeOf '{"validator":"<hex>"}'` → `total` ≥ floor;
`rpc stell_getValidators` → your id listed with power `≥ 1` once inside
the top 250.

## 8. Election + proposing (automatic — nothing to submit)

No election transaction exists. At the height boundary the runtime
re-derives the set from the staking ledger; the top 250 by total stake
propose and vote with weight = power. You are proposing when your id is in
`stell_getValidators` **and** `stell_blockNumber` advances with your node
voting (no `view change` storm, `OPERATIONS.md` §4/§14.1).

- `fragile: true` in `stell_getValidators` = quorum needs 100 % of the set
  — add validators before you rely on the chain (`OPERATIONS.md` §5).
- Downtime costs: **42 consecutive misses** (`DOWNTIME_MISS_THRESHOLD`) →
  **0.1 %** slash; equivocation → **5 %** (`OPERATIONS.md` §5). At the live
  fleet's 400 ms block interval 42 misses is ~17 s (the code default is
  50 ms, ~2.1 s) — keep the host inside the §1 sizing table.

## 9. Claim rewards — `stell-wallet claim-rewards`

```sh
stell-wallet claim-rewards --validator <YOUR-64-HEX>
# delegator claiming from a third-party validator:
stell-wallet claim-rewards --validator <OTHER-HEX> --delegator
```

Builds `SysCallClaimRewards` (own validator rewards) or
`SysCallClaimDelegatorRewards` (delegated rewards)
(`stell-wallet/src/main.rs:233`; opcodes `src/svm.rs:456-462`).
Validator-side split: `commission = delegated_share · commission_bps / 10000`
(`src/staking.rs:1939-1949`). Claimed funds land back in the bonded
position / spendable balance per the ledger — confirm with
`stell_getBalance` + `stell_stakeOf`.

## 10. Unbond — `stell-wallet unbond` (2-day window), then withdraw

```sh
stell-wallet unbond --validator <YOUR-64-HEX> <AMOUNT-STELL>
```

- Builds `SysCallUnbond { validator, amount }`
  (`stell-wallet/src/main.rs:189`, `:1523`). **Only the validator itself**
  may unbond its own stake (`src/svm.rs:1788-1798`).
- Funds enter a cooldown entry releasable after `UNBONDING_PERIOD_SECS` =
  **2 days** (`src/staking.rs:206`, `:1093`). Partial unbonds are allowed;
  the remainder keeps validating.

```sh
stell-wallet withdraw-unbond --validator <YOUR-64-HEX>   # SysCallUndelegate
```

- Pays **only matured** cooldown entries; errors while still maturing
  (`stell-wallet/src/main.rs:225`). Delegations use the two-step variant:
  `begin-unbond` (`SysCallBeginUndelegate`) then `withdraw-unbond`
  (`SysCallUndelegate`) (`stell-wallet/src/main.rs:213`, `:225`).
- Track: `stell_stakeOf` (bonded total falls only after withdrawal).

## 11. Rotate the consensus key (optional) — `rotate-key`

```sh
stell-wallet rotate-key <NEW-64-HEX>
```

Atomic move of the whole record (bond, delegations, rewards, unbonding,
slash history) to the new key; only the old key may authorize
(`stell-wallet/src/main.rs:248`; `SysCallRotateValidatorKey`,
`src/svm.rs`). Never merges into an existing record.

---

## Troubleshooting (symptom → fix)

| Symptom | Cause | Fix (verified command) |
| --- | --- | --- |
| Bonded but never in `stell_getValidators` | outside top 250 / below floor | top up via `stake`; check `stell_stakeOf` vs floor (§7) |
| `stake below the governed minimum` revert | amount under `ctx.min_validator_bond` | bond ≥ 1100 STELL (§0) |
| Ejected / power fell (slash) | downtime 0.1 % / equivocation 5 % | **re-bond** with `stake` to clear the floor again; fix the host first (`OPERATIONS.md` §5) |
| Node resumes at a stale round, never finalises | stale consensus lock | `scripts/stell-sync.sh lockclear <node> [--force]` — read-only plan first, refuses when the lock is not ahead (`OPERATIONS.md` §15, Step 5; tool `scripts/tools/stelops/`, `checkpoint` / `clear-lock --force`) |
| On a different pubsub topic, zero messages | `STELL_SHARDS` drift (e.g. `0` vs `0,1`) | `scripts/stell-sync.sh preflight` names it; fix env, restart (`OPERATIONS.md` §15, Step 4) |
| Full inodes, node silently drops out | orphan chunks (incident: 463 589 files, `df -i` = 100 %) | `scripts/node-prune-cron.sh --dir <node> [--dry-run]`; install the timer on **every** node (`OPERATIONS.md` §15.6) |
| Faucet drips stuck `pending` forever | faucet nonce gap after mempool wipe / cross-shard drip | clamp is automatic on restart (`OPERATIONS.md` §7.4); fund the faucet's own shard only (`RPC.md` §4) |
| `genesis state root mismatch`, exits nonzero | changed `validators:` / faucet key / binary | restore the original config — there is no override flag (`OPERATIONS.md` §3) |
| Key files refuse to load | wrong/missing passphrase, `0644` modes | `OPERATIONS.md` §14.2 checklist; `chmod 700 ./keys && chmod 600 ./keys/*.key` |

Pre-deploy, always: `scripts/stell-sync.sh preflight || exit 1`
(`OPERATIONS.md` §15.3). Health screen: `scripts/stell-sync.sh health`.
