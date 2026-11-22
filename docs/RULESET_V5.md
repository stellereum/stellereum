# RULESET V5 — chain-wide supply cap

> **SUPERSEDED by ruleset v6** (`docs/RULESET_V6.md`, `FORK_ID = 0x0f584a46`).
> The v5 supply rules are unchanged and still current; only the lock/rescue
> rules and the fork id moved. Do not use the v5 fork id as the current one.

Ruleset 5 is a hard fork. Old and new binaries must not form a chain together:
the fork id differs and the shard header commitment carries a new field.

| Field | Value |
|---|---|
| `PROTOCOL_VERSION` | 1.0 |
| `CONSENSUS_RULESET_VERSION` | **5** |
| `DOMAIN_SET_VERSION` | **3** (the `SHMINT01` block-hash domain was added) |
| `FORK_ID` | **`0x9d59096b`** |
| Rules folded into the fork id | **23** (21 from ruleset 4 + 2 below) |
| Genesis | new (pre-v5 data directories are refused) |

## New rules (appended, order preserved)

| # | Rule | Value | Why it is consensus |
|---|---|---|---|
| 22 | `tokenomics::CHAIN_SUPPLY_PARTITION_VERSION` | `1` | The partition of `TOTAL_SUPPLY_CAP` across the committed shard set is deterministic state; changing the scheme redefines a valid mint. |
| 23 | `tokenomics::TOTAL_SUPPLY_CAP` | `1_000_000_000_000_000_000` (1B STELL, nano) | Moving the cap changes what supply states are valid. |

## What ruleset 5 changes

1. **The 1B cap is chain-wide, not per engine.** `SupplyPartition` splits the cap
   across the committed shard set; each shard engine is handed its quota and
   `reserve_mint_nano` enforces it. `sum(quota_i) <= cap`, so
   `sum(minted_i) <= cap` for every interleaving and every lag.
2. **The shard header commitment carries `minted_total_nano`** (cumulative,
   genesis included). It is inside the masterchain block hash and signed by the
   quorum. The masterchain keeps a committed aggregate over shard heads and
   **refuses** a workchain head that would push the aggregate over the cap.
3. **Self-limiting workchains.** A workchain mints only within its static quota;
   the committed aggregate can tighten the limit (`min(share, cap - others)`) but
   never loosen it. A stale view therefore causes **stranded headroom, never
   extra supply**. Dynamic headroom sharing would need a two-phase quota
   handoff; it is deliberately not implemented.
4. **Restart.** `FinalizedHeaderRegistry` recomputes the aggregate as a pure
   function of committed heads; the registry snapshot version is 2, so a pre-v5
   blob fails closed instead of silently under-counting.

## Upgrade note

This is a **new genesis**: the header commitment layout, the fork id and the
mint guard all changed. `docs/SUPPLY_CAP.md` has the model and the failure
modes; `docs/UPGRADE_AND_RECOVERY.md` has the operator procedure.
