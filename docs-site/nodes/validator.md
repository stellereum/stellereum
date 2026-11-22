---
title: Run a validator
description: Cold/hot keys, 1,100 STELL bond, registration, staking CLI, jail, rotation and governance.
outline: deep
---

# Run a validator

A validator proposes and votes on blocks. It needs stake, a **cold withdrawal
key** and a **hot voting key**. It is the practical runbook and the exact CLI reference for `stellereum validator` and `stellereum gov`.

::: warning Economics and reality
Testnet only. There is no external audit. Run a validator only with keys and
stake you can lose. Quorum is `floor(2·power/3)+1`: two- and three-validator
networks halt on a single outage. **Run four or more** before depending on the
chain.
:::

## Roles and keys

| Key | File | Where it lives | Signs |
| --- | --- | --- | --- |
| Cold withdrawal | `withdrawal.key` | offline / cold storage after registration | register, stake, unbond, withdraw, unjail, commission changes, voting-key rotation, withdrawal-address change |
| Hot voting | `falcon.key` | validator host | BFT votes and proposals |
| Node identity | `identity.key`, `e2e.key`, `pq-identity.key` | validator host | transport, peer identity, node id |
| Consensus (legacy) | `validator.key` | validator host | Ed25519 `ValidatorId` half |

The **validator id** is not simply an address. It is derived from the chain
id, the cold withdrawal address and the voting public key:

```text
validator_id = derive_validator_id(chain_id, withdrawal_address, voting_pubkey)
```

Treat it as immutable. Every lifecycle command takes `--validator-id <64 hex>`.

::: danger The cold key is the authority
`unbond`, `withdraw`, `unjail`, `claim-rewards`, commission changes and
voting-key rotation are authorized by the **cold withdrawal key** (Ruleset v7),
not by the hot key. Keep `withdrawal.key` off the validator host after
registration. The hot key can vote; it cannot move or unbond stake.
:::

## Bond floor

| Rule | Value |
| --- | --- |
| `MIN_VALIDATOR_BOND` | **1,000 STELL** |
| `STELL_MIN_BOND_BUFFER` | **100 STELL** admission buffer |
| New-bond floor | **1,100 STELL** self-bond (`required_bond_floor_nano`) |
| Election | automatic, top **250** by total stake |
| Genesis bond | 1,000 STELL, power 1 |
| Unbonding period | **2 days** (`UNBONDING_PERIOD_SECS`) |
| Max active validators | **250** |

A bare 1,000-STELL bond is refused at admission. Below the top 250 you are
bonded but **not proposing**.

## Hardware

| Role | vCPU | RAM | Disk |
| --- | --- | --- | --- |
| validator | **≥ 4** | **≥ 8 GB** (node process capped `MemoryMax=2G`) | **≥ 100 GB SSD**, < 80 % used |

**1 vCPU is explicitly insufficient for a validator.** Live measurements show
scheduler starvation (>63 % sys / 36 % iowait, load ~4), 0.35–2 s transport
round-trips dominating consensus, and four consensus loops on one vCPU costing
~25 % throughput. The same code on a 6-core host does 571–792 TPS — the
bottleneck is iron, not architecture.

## Step 1 — generate keys

```bash
export STELL_NODE_PASSPHRASE='<long random passphrase>'

stellereum keys init --keys-dir ./keys
# cold withdrawal key, separate file:
stellereum keys init --keys-dir ./keys --falcon-file ./keys/withdrawal.key
```

`keys init` uses the same `load_or_generate` path as `run` and is idempotent:
existing keys are loaded, never overwritten. Permissions: directory `0700`,
files `0600`, encrypted at rest (`enc2:`) by default.

Without a passphrase in `STELL_NODE_PASSPHRASE` / `STELL_KEY_PASSPHRASE` /
`INFNODE_KEY_PASSPHRASE` (first non-empty wins), the node refuses to write
keys unencrypted.

## Step 2 — print the peer stanza

```bash
stellereum keys peer-stanza \
  --keys-dir ./keys \
  --name validator-$(hostname -s) \
  --endpoint <PUBLIC_IP>:9410
```

Outputs `node-id`, `ed-pub`, `x-pub`, `falcon-pub` — public keys only. Send
this file to the network admin; it is the one thing you share.

## Step 3 — join as an observer first

```bash
scripts/join-testnet.sh --mode validator \
  --home "$HOME/stell-validator" \
  --name validator-$(hostname -s) \
  --listen 0.0.0.0:9410 \
  --advertise <PUBLIC_IP>:9410 \
  --non-interactive
```

This:

- initializes `keys/falcon.key` and `keys/withdrawal.key`;
- writes `node.yaml`, `node.env` with `STELL_OBSERVER=1`;
- bootstraps from `https://rpc.stellereum.org/snapshot/latest.tar.zst`;
- prints the validator id and withdrawal address from a `--dry-run`
  registration.

Start it and **wait until fully synced**:

```bash
cd ~/stell-validator
set -a; source node.env; set +a
stellereum run --config node.yaml --shard 0 --parallel-exec

# in another shell
curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_syncing","params":[]}'
# must become false; stell_blockNumber must advance
```

Do not register until `stell_syncing == false` and
`stell_getStateRoot` equals a peer's root at the same height.

## Step 4 — fund the cold withdrawal address

On the **masterchain** form:

```bash
curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_faucet",
       "params":{"address":"-1:<WITHDRAWAL_ADDRESS>","token":"<faucet token>"}}'
```

::: danger The default faucet cannot fund a 1,100 STELL bond
The default faucet drip is **2 STELL** and the per-address lifetime cap is
**50 STELL**. That is an onboarding drip, not validator capital. A bond of
1,100 STELL must come from a funded account (a network-admin transfer) or from
a faucet the operator has deliberately configured with a higher
`STELL_FAUCET_LIFETIME_CAP_STELL`. Do not plan a validator around repeated
default drips; the cap is enforced per address.

Fund at least **1,101 STELL** (1,100 bond + a small gas margin) on shard 0
(masterchain: `-1:<withdrawal_address>`). A bare workchain address will not
fund a masterchain bond.
:::

The faucet drip is a normal pending transfer. Watch it with
`stell_getTransactionStatus` until `success`.

## Step 5 — register on-chain (OpCode 59)

```bash
stellereum validator register-validator \
  --withdrawal-key-file ./keys/withdrawal.key \
  --voting-key-file ./keys/falcon.key \
  --amount 1100000000000 \
  --commission-bps 1000 \
  --rpc http://127.0.0.1:8545 \
  --chain-id 5757
```

- `--amount` is **nano-STELL** (1,100 STELL = `1100000000000`).
- `--commission-bps` is `0..=10000`; default 1,000 bps = 10 %.
- The transaction is signed by the **cold withdrawal key**, self-addressed on
  the masterchain, and carries the voting key's Falcon proof-of-possession.
- `--dry-run` prints the validator id, withdrawal address, nonce, hash and raw
  bytes without submitting. Do this first.

Verify:

```bash
stellereum validator status --validator <VALIDATOR_ID>
curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_stakeOf","params":{"validator":"<VALIDATOR_ID>"}}'
curl -s -X POST http://127.0.0.1:8545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_getValidators","params":{}}'
```

You are proposing when the id appears in `stell_getValidators` with power ≥ 1
**and** the height advances without a view-change storm.

## Step 6 — promote to validator

Only after registration is included and the id is in the set:

```bash
sed -i 's/^STELL_OBSERVER=1$/STELL_OBSERVER=0/' ~/stell-validator/node.env
systemctl restart stell-validator   # or your unit name
```

The hot key now signs votes; the cold key can stay offline.

## `stellereum validator` reference

Every subcommand accepts `--rpc` (default `http://127.0.0.1:8545`),
`--nonce`, `--chain-id`, `--dry-run` and `--token`.

### Registration and key lifecycle

| Command | Key flags | OpCode |
| --- | --- | --- |
| `register-validator` | `--withdrawal-key-file`/`--withdrawal-seed`, `--voting-key-file`/`--voting-seed`, `--amount`, `--commission-bps` | 59 `SysCallRegisterValidator` |
| `rotate-voting-key` | `--withdrawal-key-file`, `--validator-id`, `--rotation-seq`, `--new-voting-key-file` or `--cancel` | 60 `SysCallRotateVotingKey` |
| `change-withdrawal` | `--withdrawal-key-file`, `--validator-id`, `--new-withdrawal-key-file` | 61 `SysCallChangeWithdrawal` |
| `claim-withdrawal` | `--withdrawal-key-file`, `--validator-id`, `--voting-key-file` | 62 one-time pre-W3 migration |
| `announce-commission` | `--withdrawal-key-file`, `--validator-id`, `--new-bps` | 63 `SysCallAnnounceCommission` |
| `apply-commission` | `--withdrawal-key-file`, `--validator-id` | 64 `SysCallApplyCommission` |

### Staking

| Command | Key flags | OpCode |
| --- | --- | --- |
| `status` | `--validator` (read only) | — |
| `stake` | `--withdrawal-key-file`, `--validator-id`, `--amount` (nano) | `SysCallStake` |
| `unbond` | `--withdrawal-key-file`, `--validator-id`, `--amount` (nano) | `SysCallUnbond` |
| `withdraw` | `--withdrawal-key-file`, `--validator-id` | `SysCallWithdrawSelfBond` |
| `delegate` | `--falcon-key-file`, `--validator-id`, `--amount` (nano) | `SysCallDelegate` |
| `begin-undelegate` | `--falcon-key-file`, `--validator-id`, `--amount` (nano) | `SysCallBeginUndelegate` |
| `withdraw-delegation` | `--falcon-key-file`, `--validator-id` | `SysCallUndelegate` |
| `claim-rewards` | `--withdrawal-key-file`, `--validator-id`, `--delegator?` | `SysCallClaimRewards` / `SysCallClaimDelegatorRewards` |
| `unjail` | `--withdrawal-key-file`, `--validator-id`, `--top-up?` (nano) | optional `SysCallStake` + `SysCallUnjail` |

::: tip Nano-STELL, not STELL
The new `stellereum validator` commands take `--amount` in **nano-STELL**.
1 STELL = `1_000_000_000`. The older `stell-wallet stake` command takes whole
STELL. Read the help before copying a number between them.
:::

### Examples

```bash
# Inspect
stellereum validator status --validator <ID>

# Top up self-bond by 100 STELL
stellereum validator stake --withdrawal-key-file ./keys/withdrawal.key \
  --validator-id <ID> --amount 100000000000

# Begin unbonding 500 STELL
stellereum validator unbond --withdrawal-key-file ./keys/withdrawal.key \
  --validator-id <ID> --amount 500000000000

# Withdraw matured self-bond (after 2 days)
stellereum validator withdraw --withdrawal-key-file ./keys/withdrawal.key \
  --validator-id <ID>

# Delegate 250 STELL from a delegator key
stellereum validator delegate --falcon-key-file ./delegator.json \
  --validator-id <ID> --amount 250000000000

# Begin and later withdraw a delegation
stellereum validator begin-undelegate --falcon-key-file ./delegator.json \
  --validator-id <ID> --amount 250000000000
stellereum validator withdraw-delegation --falcon-key-file ./delegator.json \
  --validator-id <ID>

# Claim validator rewards
stellereum validator claim-rewards --withdrawal-key-file ./keys/withdrawal.key \
  --validator-id <ID>

# Claim delegator rewards
stellereum validator claim-rewards --withdrawal-key-file ./delegator.json \
  --validator-id <ID> --delegator
```

### `status` output

`stellereum validator status` reads `stell_getValidatorStatus`, which answers:

```json
{
  "validator": "<64 hex>",
  "known": true,
  "jailed": false,
  "jailed_at_height": null,
  "release_height": null,
  "in_set": true,
  "self_bond": "1100000000000",
  "commission_bps": 1000,
  "withdrawal_address": "<64 hex>",
  "rotation_seq": 0,
  "pending_commission": null,
  "last_commission_change_height": null
}
```

## Commission

::: warning Old docs say commission is immutable. It is not, in Ruleset v7.
`stell-wallet` / `RPC.md` still describe a bond-time-only rate. The live ledger
has a bounded commission schedule (`announce-commission` / `apply-commission`).
Use the live rules below.
:::

| Rule | Value |
| --- | --- |
| Default at registration | `DEFAULT_COMMISSION_BPS = 1_000` (10 %) |
| Maximum change per step | `COMMISSION_MAX_DELTA_BPS = 500` (5 percentage points) |
| Announce-to-effect delay | `COMMISSION_EFFECT_DELAY_HEIGHTS = 30_000` |
| Cooldown between effective changes | `COMMISSION_CHANGE_COOLDOWN_HEIGHTS = 30_000` |
| Cancel a pending change | announce the **current** rate (no-op, no cooldown) |

A raise is announced 30,000 heights before it takes effect, so delegators can
undelegate or redelegate. Announcing a different rate replaces a pending change.
`apply-commission` installs it once `effective_height` is reached; applying
early is refused (`no commission change is due …`).

```bash
stellereum validator announce-commission \
  --withdrawal-key-file ./keys/withdrawal.key \
  --validator-id <ID> --new-bps 1500

# later, after effective_height
stellereum validator apply-commission \
  --withdrawal-key-file ./keys/withdrawal.key \
  --validator-id <ID>
```

## Voting-key rotation

```bash
stellereum validator rotate-voting-key \
  --withdrawal-key-file ./keys/withdrawal.key \
  --validator-id <ID> \
  --rotation-seq <CURRENT_SEQ> \
  --new-voting-key-file ./keys/falcon-new.key
```

- `--rotation-seq` must equal the record's `next_seq` (`rotation_seq` in
  `status`).
- The new key signs a Falcon proof-of-possession bound to the chain id,
  validator id, withdrawal address, sequence and key.
- The rotation takes effect after `PQ_ROTATION_DELAY_HEIGHTS = 30_000` heights;
  the current key stays valid until then.
- `--cancel` cancels a pending rotation before its effective height.
- The last **2** keys are retained in history, so votes at recent heights still
  verify.

After the effective height, put the new key on the host and restart. A hot key
rotation does **not** change the validator id or the withdrawal address.

::: danger Rotating the node's Falcon key with `keys rotate-falcon`
`stellereum keys rotate-falcon --force` generates a **new validator address**
and requires re-staking. It is not the same operation as
`validator rotate-voting-key`. Use the on-chain rotation for a live validator.
:::

## Withdrawal-address change

```bash
stellereum validator change-withdrawal \
  --withdrawal-key-file ./keys/withdrawal.key \
  --validator-id <ID> \
  --new-withdrawal-key-file ./keys/withdrawal-new.key
```

The new key signs a proof-of-possession; the current cold key authorizes the
change. The change is immediate once included. The validator id does not
change.

## Jail and unjail

| Rule | Value |
| --- | --- |
| Downtime threshold | **42 consecutive missed heights** |
| Downtime penalty | **0.1 %** (`DOWNTIME_SLASH_BPS = 10`) |
| Downtime cooldown | 500 heights |
| Jail release delay | **4,000 heights** (`JAIL_RELEASE_DELAY_HEIGHTS`) |
| Equivocation penalty | **5 %** (`EQUIVOCATION_SLASH_BPS = 500`) |

A jailed validator is excluded from the set. It becomes eligible for `unjail`
at `release_height = jailed_at_height + 4,000`. `unjail` also requires the
self-bond to still be at or above the admission floor; a slashed validator
below the floor must top up first (the command supports `--top-up`).

```bash
# see the state
stellereum validator status --validator <ID>

# after release_height, with an optional top-up
stellereum validator unjail \
  --withdrawal-key-file ./keys/withdrawal.key \
  --validator-id <ID> \
  --top-up 50000000000
```

A validator that cannot stay inside the hardware table will be jailed again.
Fix the host before unjailing.

### Claim a withdrawal address before you need it

`unjail`, `unbond`, `claim-rewards`, `withdraw` and the commission opcodes are
owner operations: the transaction must be sent by the validator's cold
`withdrawal_address`. A validator registered **before** the withdrawal field
existed has `withdrawal_address = null`, and under Ruleset v7 that makes every
owner operation impossible — a jail would lock the bond with no in-band
recovery.

`stellereum validator status` prints this explicitly:

```text
MANAGEABILITY: OK (withdrawal 9be3…4335)
MANAGEABILITY: UNMANAGEABLE: no withdrawal_address — unjail/unbond/withdraw
                will be refused; run validator claim-withdrawal
```

The one-time migration is `claim-withdrawal` (OpCode 62). It needs two keys:

- the **hot voting key** — it signs the claim preimage, proving the validator
  consents;
- a **cold withdrawal key** — its PQ address becomes the new
  `withdrawal_address` and it sends the transaction.

```bash
# 1. create a cold key (keep it offline in production)
stellereum keys init --keys-dir ./keys --falcon-file ./keys/withdrawal.key

# 2. the new address needs gas before the transaction can be included
stellereum wallet address --falcon-key-file ./keys/withdrawal.key
#    -> fund that address from the faucet or an operator transfer

# 3. claim, then verify
stellereum validator claim-withdrawal \
  --withdrawal-key-file ./keys/withdrawal.key \
  --voting-key-file   ./keys/falcon.key \
  --validator-id      <ID>
stellereum validator status --validator <ID>   # MANAGEABILITY: OK
```

Do this on **every** validator you operate, before it is ever jailed.
::: warning Cold keys belong offline
`claim-withdrawal` and `change-withdrawal` accept a key file on the node only
for convenience. On mainnet, generate the cold key on an offline machine and
keep an encrypted backup; losing it means losing the bond.
:::

::: tip Misses are counted from finalized evidence
Every node derives the miss count from the finalized block's embedded parent
QC, so all nodes agree. Signing again resets the counter. The cooldown skips
the first offence on chains younger than 500 blocks. A halted network slashes
nobody: no blocks, no evidence.
:::

## Rewards

Delegator rewards use an F1-style reward-per-token accumulator, not a history
walk. Nothing accrues to spendable balance until claimed.

```bash
stellereum validator claim-rewards \
  --withdrawal-key-file ./keys/withdrawal.key \
  --validator-id <ID>

stellereum validator claim-rewards \
  --withdrawal-key-file ./delegator.json \
  --validator-id <ID> --delegator
```

The validator's share is `delegated_share · commission_bps / 10000`. Confirm
with `stell_getBalance` and `stell_stakeOf`.

## `stellereum gov` reference

Governance writes are **block-carried**: `SysCallGovPropose` and
`SysCallGovVote` ride ordinary transactions. The sender is the proposer/voter.

| Command | Flags | Purpose |
| --- | --- | --- |
| `gov list` | `--rpc` | list proposals |
| `gov show` | `--id`, `--rpc` | one proposal |
| `gov params` | `--rpc` | quorum, `next_id`, applied overrides |
| `gov propose` | `--falcon-key-file`/`--falcon-seed`, `--title`, `--action`, `--params`, `--proposal-id?`, `--height?`, `--nonce?`, `--chain-id?`, `--dry-run`, `--token?` | submit a proposal |
| `gov vote` | `--falcon-key-file`/`--falcon-seed`, `--id`, `--choice`, `--height?`, `--nonce?`, `--chain-id?`, `--dry-run`, `--token?` | cast a vote |

### Examples

```bash
stellereum gov list
stellereum gov show --id 4
stellereum gov params

# Signal proposal
stellereum gov propose \
  --falcon-key-file ./keys/falcon.key \
  --title "raise the floor" \
  --action signal \
  --params '{"text":"raise min gas to 300k"}'

# Parameter change
stellereum gov propose \
  --falcon-key-file ./keys/falcon.key \
  --title "raise min gas" \
  --action set_min_gas_limit \
  --params '{"value":300000}'

# Software upgrade plan (see /nodes/upgrades)
stellereum gov propose \
  --falcon-key-file ./keys/falcon.key \
  --title "v0.2.0" \
  --action software_upgrade \
  --params '{"name":"v0.2.0","height":250000,"sha256":"<64 hex>"}'

# Vote
stellereum gov vote --falcon-key-file ./keys/falcon.key --id 4 --choice yes
```

`--proposal-id` defaults to `stell_governanceParams.next_id`;
`--height` defaults to `stell_blockNumber + 1`. Both must match what the block
will apply, so read them immediately before building. `--dry-run` prints the
signed transaction instead of submitting.

::: warning A proposer needs 10,000 STELL of stake
`PROPOSAL_MIN_STAKE_NANO` is 10,000 STELL. A smaller proposer gets
`-32000 "propose failed: …"`. Voting is open for 3 days; quorum is
`quorum_bps = 6666`; a passed action has a 90,000-height timelock.
:::

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `stake below the governed minimum` | amount < `ctx.min_validator_bond` | bond ≥ 1,100 STELL |
| Bonded but not in `stell_getValidators` | outside top 250 / below floor | top up; check `stell_stakeOf` |
| `unauthorized` on unbond/unjail | signed by the hot key or wrong withdrawal key | use the cold withdrawal key |
| `validator is jailed` | downtime | wait for `release_height`, then `unjail` |
| `no commission change is due` | effective height not reached / cooldown / nothing pending | read `status.pending_commission` |
| `ValidatorIdMismatch` / PoP refused | wrong `--validator-id`, chain id or new key | rebuild from `status` and the node's chain id |
| Node never finalizes after a restart | stale consensus lock | see [Operations](/nodes/operations#stale-consensus-lock) |
| Ejected / power fell | slash | re-bond to the floor, then fix the host |
| `genesis state root mismatch` | changed validator set/faucet key/binary | restore the network config; don't wipe blindly |

## Next

Continue with [Operations](/nodes/operations) for host hardening and backups, and [Upgrades](/nodes/upgrades) for governed binary swaps. [Consensus & finality](/core-concepts/consensus-finality) explains the quorum your validator joins.
