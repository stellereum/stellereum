# Stellereum — Community Validator Guide (public testnet)

Chain id `5757` known (`stellereum/src/zkml.rs:220`; env `STELL_CHAIN_ID` `:226`).
Public RPC / faucet URL / tokens / peer set: `TBD-operator`.
No `bond`/`unjail` CLI exists — staking submits through JSON-RPC prepare methods (names verified below); endpoint + signing flow marked where operator-dependent.

## 1. Keygen — PQ Falcon via CLI (exact, verified)

```bash
stellereum wallet generate
# prints: Address, Private Key, Viewing keys, Stealth pub (verified output 2026-11-04)

stellereum keys init --keys-dir ./keys
# idempotent; 0700 dir / 0600 files; same mechanism `run` uses (keys --help)

stellereum keys peer-stanza --keys-dir ./keys --name <node> --endpoint <PUBLIC-IP:9410>
# ready block for the admin -> scripts/add-peer.sh

# Falcon rotation (local file; CHANGES validator address — re-stake separately):
stellereum keys rotate-falcon --keys-dir ./keys --falcon-file ./keys/falcon.key --force
# --force required when a key exists (rotate-falcon --help); old file backed up to <file>.bak-<ts>
```
Node keys at rest are encrypted (`enc2` Argon2id + XChaCha20) with `STELL_KEY_PASSPHRASE` in `node.env` (`0600`); back up `./keys` + passphrase together (`join-network.sh:172-191,343-346`).

## 2. Faucet — first coins

- Code defaults (actual public values `TBD-operator` — operator may override via env):
  - `stell_faucet` drip `10 STELL` default (`src/rpc.rs:718-727` `Faucet::default_drip_nano`, `STELL_FAUCET_DRIP_STELL` override), lifetime cap `1_000 STELL` per address (`src/main.rs:1103` `FAUCET_LIFETIME_CAP`), genesis faucet balance `1_000_000_000_000_000 nano` (`src/main.rs:1095`), per-IP `20/hr` (`src/rpc.rs:332-334`).
  - Gated by separate `STELL_FAUCET_TOKEN`, fail-closed (`src/rpc.rs:4691-4704`; explorer `src/explorer.rs:569-599`). Faucet disabled by default (`src/main.rs:8092` path; `docs/TESTNET_COMPLETENESS.md:115`).
- Verified RPC shape (`docs/RPC.md:1061-1067,2648`):
```bash
curl -s -X POST TBD-operator-RPC -H 'content-type: application/json' \
 -d '{"jsonrpc":"2.0","id":1,"method":"stell_faucet","params":{"address":"<64hex>"}}'
# masterchain form: {"address":"-1:<hex>"} (docs/OPERATIONS.md:1095)
```
- Confirm: `stellereum wallet balance --help` / `stell_getBalance` shows the drip; fund the validator address to ≥ bond floor before bonding.

## 3. Bond tx — minimum from code

- Floor (fail-closed): `required_bond_floor_nano() = MIN_VALIDATOR_BOND + STELL_MIN_BOND_BUFFER` (`src/staking.rs:81-83`):
  - `MIN_VALIDATOR_BOND = 1_000 * 1_000_000_000` (1,000 STELL) `:62`
  - `STELL_MIN_BOND_BUFFER = 100 * 1_000_000_000` (100 STELL) `:78`
  - **New bond MUST carry ≥ 1,100 STELL self-bond** or `bond()` returns `BondBelowMinimum` (`:1097-1108`, error `:350`, message `:437-450`). Bare-MIN (1,000) cannot be created — one 0.1% slash would eject it (`:44-50`).
- Submit path (verified names, endpoint `TBD-operator`): prepare `stell_stakeBond {validator, amount}` (`src/native_api.rs:190-196` spec; handler `:1265-1279` -> `SysCallStake`, gas `GAS_STAKE_BOND=2_000` `src/svm.rs:92`), sign, submit via `stell_sendRawTransaction`. Top-ups use `add_bond` (fail-open below floor but WARNs, `:1181-1196`); `set --commission_bps ≤ 10_000` or `BadCommission` (`:1109-1110`, `BPS_DENOMINATOR=10_000` `:301`).
- After bonding, the admin must include your id in every node's `validators:` for genesis-coordinated sets; live promotion is coordinated (`OPERATIONS.md §10` per `join-network.sh:540-542`). Never flip `STELL_OBSERVER=0` on a live chain and hope.

## 4. Election — how it works (2 sentences)

`StakingLedger::to_validator_set()` (`src/staking.rs:2016-2031`) filters to `self_bond ≥ min_bond` and not jailed, ranks by total power (`self_bond + delegated`) with validator-id tiebreak, and truncates to `MAX_ACTIVE_VALIDATORS = 250` (`:209`); full/RPC/archive nodes are unlimited, only consensus voters are capped. The derived set takes effect at the `H+1` activation boundary (`:2010-2015`), so every stake/slash/jail applies at the next height, never mid-flight.

Target health: `TARGET_MIN_VALIDATORS = 150` (`:214`, non-enforced).

## 5. Rewards / commission / unbonding numbers (all `src/staking.rs` unless noted)

- Block reward: `BLOCK_REWARD_NANO = 317_000_000` (0.317 STELL) per block, divided by active validators (`src/tokenomics.rs:14-21,277-302`); emmission capped at `REWARDS_EMISSION_CAP = 350_000_000 STELL` (`staking.rs:235`); jailed validators earn nothing (`distribute_reward` `:3037-3041`); delegator share accrues lazily via `REWARD_PER_TOKEN_SCALE` (`:712`).
- Default commission `DEFAULT_COMMISSION_BPS = 1_000` = 10% on delegated rewards (`:296`); 100% allowed but pays delegators 0. Changes only via announce→apply: max step `COMMISSION_MAX_DELTA_BPS = 500` (5pp) (`:325`), delay `COMMISSION_EFFECT_DELAY_HEIGHTS = 7_200` (~6h at 3s blocks) (`:337`), cooldown `COMMISSION_CHANGE_COOLDOWN_HEIGHTS = 7_200` (`:346`); pending schedule queryable via `stell_getValidatorStatus` (`:1270-1273`).
- Delegation min `MIN_DELEGATION = 1 STELL` (`:237`); unbonding cooldown `UNBONDING_PERIOD_SECS = 2*24*3600` (~2 days) (`:242`); `stell_delegate / stell_undelegate / stell_claimRewards / stell_stakeWithdraw` are the prepare methods (`src/native_api.rs:211-231`; `is_native_method` list `src/rpc.rs:8539-8547`).

## 6. Unjail flow

Jail installs on a downtime slash (`note_missed_heights` → `slash_downtime`, `staking.rs:2939-2949`); `is_jailed` excludes from the set (`:1199-1203`). `unjail(validator, now_height)` (`:1234-1268`) requires ALL: (1) jailed else `NotJailed`, (2) `now_height ≥ release_height` (`JAIL_RELEASE_DELAY_HEIGHTS = 1_000` ≈ 50 min at 3s blocks, `:315`), else `CooldownNotElapsed`, (3) `self_bond ≥ 1,100 STELL floor` else `BondBelowMinimum` (top up via `add_bond` while jailed — allowed, `:1222-1224`). Effects: record removed, `missed=0`, loud `VALIDATOR-UNJAIL … verify it is actually online` WARN (`:1256-1260`), history preserved. Check status with `stell_getValidatorStatus` / `stell_getValidators` (`src/rpc.rs:5461-5507`); submission RPC name is operator-wired — `TBD-operator` (no verified one-line CLI; do not invent one).

## 7. Rotation of PQ keys (delay const)

On-chain registry `PqRegistry` (`src/pq_registry.rs`): `announce_rotation` stages a replacement that takes effect at `now + PQ_ROTATION_DELAY_HEIGHTS`, `PQ_ROTATION_DELAY_HEIGHTS = 7_200` (~6h) (`:101`); current key stays authoritative until then, history keeps `PQ_KEY_HISTORY_LIMIT = 2` (`:110`), cap `PQ_MAX_KEY_BYTES = HYBRID_PUBKEY_LEN` (`:119`). Hooks: `pq_register_key / pq_announce_rotation / pq_apply_rotation` (`staking.rs:2516,2621`); cancel by re-announcing the current key; reads resolve the key *at the vote's height*. Local file rotation (`keys rotate-falcon --force`) is SEPARATE and changes the address — on-chain rotation is the coordinated path.

## 8. Slashing rules (cite)

- Equivocation (double-sign): `EQUIVOCATION_SLASH_BPS = 500` = 5% of total slashable (self + delegated + in-flight unbonding) (`staking.rs:247`, burn math `:2086-2141`).
- Downtime: `DOWNTIME_SLASH_BPS = 10` = 0.1% (`:257`) once `missed ≥ DOWNTIME_MISS_THRESHOLD = 10` consecutive heights (`:262`), at most every `DOWNTIME_PENALTY_COOLDOWN = 100` heights (`:268`); triggers jail (above). Near-floor remainders emit `SLASH-EJECT-WARN` / `SLASH-EJECT … re-bond to MIN+buffer` (`:157,174`).
- Micro-committee equivocation: `MICRO_COMMITTEE_SLASH_BPS = 10_000` = 100%, validator removed (`:252,2860-2863`).

## 9. Exit / unbond flow

`unbond(validator, amount, now)` (`:1548-1581`): `amount ≤ self_bond` else `InsufficientBond`; remaining must be `0` (full exit) or `≥ 1,100 STELL floor` else `BondBelowMinimum`; pushes an `UnbondingEntry {release_at = now + UNBONDING_PERIOD_SECS}`. `undelegate` is the delegator mirror (unlimited concurrent batches; `UnbondingInProgress` reserved, `:359-367`). After cooldown, `withdraw()` / `withdraw_delegator()` credit from `STAKING_POOL` (`runtime.rs:2331-2424` pool-backed discipline). Prepare methods: `stell_stakeUnbond`, `stell_stakeWithdraw`, `stell_undelegate` (`native_api.rs:197-209`); cooldown/maturity is wall-clock seconds, rewards stop at unbond time.
