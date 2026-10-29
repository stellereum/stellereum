# Validators — the staking bible

All numbers grepped from `src/staking.rs` (symbol named per row).
Full click-by-click runbook: `docs/VALIDATOR_ONBOARDING.md`.

## Bond floors

| Rule | Value | Source |
| --- | --- | --- |
| `MIN_VALIDATOR_BOND` | **1000 STELL** | `src/staking.rs:59` |
| `STELL_MIN_BOND_BUFFER` | **100 STELL** admission buffer | `src/staking.rs:72` |
| New-bond floor | **1100 STELL** self-bond | `required_bond_floor_nano` (`:62`) |
| Election | auto, top **250** by total stake | `MAX_ACTIVE_VALIDATORS` (`:190`) |
| Genesis bond | 1000 STELL, power 1 | `fund_genesis` (`docs/RPC.md` §5) |

A bare 1000-STELL bond is refused at admission. Below the top 250 you
are bonded but not proposing. Bond via `SysCallStake`
(`stell-wallet stake --validator <hex> 1100`; `--dry-run` first).
Quorum is `floor(2·power/3)+1`: 1→1, 2→2, 3→3, 4→3, 5→4 — so 2- and
3-validator nets halt on one outage; **run four or more**
(`docs/OPERATIONS.md` §5).

## Commission immutability

Commission is set **once at bond time** from governance
(`ctx.default_commission_bps`, default `DEFAULT_COMMISSION_BPS` =
**1000 bps = 10 %**, `src/staking.rs:232`); the ledger has **no setter**,
the opcode carries no commission field, and the wallet `stake` command
offers no `--commission-bps` — deliberately unimplemented
(`docs/RPC.md` §5). A later `SetDefaultCommissionBps` vote prices **new**
bonds only. Pick your validator accordingly: the rate is forever.

## Rewards (F1 lazy — how and when claimed)

Delegator rewards use an F1-style **reward-per-token accumulator**
(`PROTOCOL.md` §1.4; `reward_accumulators`, `src/staking.rs:513–833`):
one growing rate per validator + per-pair checkpoints, not a history
walk. The accumulator, pools, carried remainder **with its denominator**,
and checkpoints are consensus-committed (`STAKING_REWARD_ACC_V1` domain)
— a stale checkpoint would double-pay. Nothing accrues to spendable
balance until claimed:

```sh
stell-wallet claim-rewards --validator <YOUR-HEX>            # own rewards
stell-wallet claim-rewards --validator <OTHER-HEX> --delegator
```

Opcodes `SysCallClaimRewards` / `SysCallClaimDelegatorRewards`
(`src/svm.rs:456–462`); validator split
`commission = delegated_share · commission_bps / 10000`
(`src/staking.rs:1939–1949`). Confirm with `stell_getBalance` +
`stell_stakeOf`. Unclaimed rewards sit in the minted-but-unclaimed pool.

## Slashing

Evidence-driven only, never local timers (`PROTOCOL.md` I5):

| Offence | Penalty | Cooldown | Source |
| --- | --- | --- | --- |
| downtime (10 consecutive misses) | **0.1 %** burn (`DOWNTIME_SLASH_BPS`=10 bps) | 100 heights (`DOWNTIME_PENALTY_COOLDOWN`) | `src/staking.rs:226–231` |
| equivocation (double-vote) | **5 %** burn (`EQUIVOCATION_SLASH_BPS`=500 bps) | none | `src/staking.rs:222` |

Misses derive from the finalized block's embedded parent QC, so every
node counts identically; signing again resets the counter; the cooldown
skips the first offence (chains < 100 blocks). Burns debit the staking
pool for real. Genesis math: 1000 STELL bond loses 1 STELL per downtime
hit, 50 per equivocation. At the 400 ms block floor, 10 misses ≈ 4 s —
a GC pause can cost you (`OPERATIONS.md` §5). A halted 2-validator net
slashes nobody (no blocks, no evidence). `missed` has no RPC — watch
`stell_stakeOf` for a `total` below your bond.

## Unbonding window

`UNBONDING_PERIOD_SECS` = **2 days** (`src/staking.rs:206`). Only the
validator itself may unbond (`src/svm.rs:1788–1798`); partial unbonds
allowed, remainder keeps validating. Withdraw after maturity
(`withdraw-unbond` → `SysCallUndelegate`); delegations use
`begin-unbond` then `withdraw-unbond`. There is no "leave the set"
fast path — plan maintenance as downtime, not exit.

## Hardware (honest)

1 vCPU is **explicitly insufficient** for a validator
(`docs/OPERATIONS.md` §1): measured live — scheduler starvation
(>63 % sys / 36 % iowait, load ~4), 0.35–2 s transport RTT dominating
consensus, four consensus loops on 1 vCPU costing ~25 % throughput, and
the recorded verdict *"1vCPU не потянет два консенсуса"*. Reference host
(Ryzen 5 3600, 6-core/16 GB) does 571–792 TPS — ×5–6 the 1-vCPU stand.

| Role | vCPU | RAM | Disk |
| --- | --- | --- | --- |
| validator | ≥ 4 | ≥ 8 GB (process capped `MemoryMax=2G`) | ≥ 100 GB SSD, < 80 % used |
| observer | ≥ 2 | ≥ 4 GB | ≥ 60 GB SSD |

Spinning disk stalls the persist queue and reads as consensus lag.

## Onboarding runbook (commands)

```sh
stellereum keys init --keys-dir ./keys
stellereum keys peer-stanza --keys-dir ./keys --name node-e
scripts/join-network.sh --faucet-key <64-HEX> --advertise <IP:9410> \
  --peers-file <admin-set.yaml>     # new nodes start STELL_OBSERVER=1
stellereum node-bootstrap --config node.yaml --shard 1
rpc stell_faucet '{"address":"-1:<YOUR-HEX>"}'   # masterchain form
stell-wallet stake --validator <YOUR-HEX> 1100
```

Troubleshooting table (stale lock, topic drift, nonce gaps, genesis
mismatch): `VALIDATOR_ONBOARDING.md` §Troubleshooting and
[05-operators](05-operators.md) failure-mode table.
