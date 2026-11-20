# Consensus ruleset v3 — shard-bound votes, fork id `0xb13baff4` (new genesis)

> **SUPERSEDED by ruleset v6** (`docs/RULESET_V6.md`, `FORK_ID = 0x0f584a46`).
> This page is the historical v3 rationale; the shard-bound vote preimage
> (`STELLEREUM_BFT_VOTE_V3`) is still current, but the fork id and all
> subsequent rules (signed round, timestamp bound, supply cap, lock identity)
> are not.

**Status:** deliberate consensus change (ruleset v3). **Activation:** new
genesis; there is no in-place activation height. Ruleset v2 and ruleset v3
binaries refuse consensus participation with each other because `FORK_ID`
changed, so a mixed fleet fails closed at the handshake instead of silently
diverging.

- `CONSENSUS_RULESET_VERSION = 3` (`stellereum/src/protocol.rs`)
- `DOMAIN_SET_VERSION = 2`
- `FORK_ID = 0xb13baff4` (was `0x3b768f7a` under ruleset v2,
  `0xc5ddb707` under the historical v1)

The ruleset-v2 height calibration (`docs/RULESET_V2.md`) is unchanged and is
inherited by v3: every v2 rule value is still folded, in the same order.

---

## 1. Why the vote signature changed (`STELLEREUM_BFT_VOTE_V3`)

The vote preimage is now:

```text
STELLEREUM_BFT_VOTE_V3 ‖ chain_id(8, BE) ‖ shard_id(4, BE)
    ‖ height(8, BE) ‖ round(4, BE) ‖ kind(1) ‖ target(1 + 32)
```

Ruleset v2 and earlier signed the same fields **without the shard id**
(`STELLEREUM_BFT_VOTE_V2`). That was a false-slash primitive: one validator
key may legitimately run on several shards at once, and each shard has its own
block space, so the same key honestly signs DIFFERENT targets at the same
`(height, round, kind)` — one target per shard. Without the shard in the
preimage, an observer could take the honest shard-0 and shard-1 votes, relabel
both with a single shard id, and present a cryptographically valid
equivocation pair that slashes an honest validator.

Binding `shard_id` into the signed bytes makes a shard-0 signature invalid as
a shard-1 vote (and vice versa), so relabeling no longer verifies. Because the
preimage changed, the domain tag was bumped `V2 -> V3`: old signatures do not
verify and fail closed instead of being reinterpreted. `shard_id` is also part
of the `Vote` and `QuorumCertificate` wire encoding (old certificates decode
with the serde default, the masterchain shard 0).

The domain is folded into `FORK_ID` beside the other consensus wire/signature
domains:

```text
STELL_FORK_ID_V1 ‖ domain_set_version(4, LE) ‖ chain_id(8, LE)
    ‖ ruleset_version(4, LE)
    ‖ "STELL_SORTITION_V5"
    ‖ "STELLEREUM_EQUIVOCATION_OFFENSE_V2"
    ‖ "STELLEREUM_PROPOSAL_EQUIVOCATION_OFFENSE_V2"
    ‖ "STELLEREUM_BFT_VOTE_V3"          <- new in v3
    ‖ "STELL_VOTEFAL_V1"
    ‖ "STELL_UQC_PQ_V5_"
    ‖ "STELL_QC_PQ_V5__"
    ‖ 20 × u64 rule constants (LE)
```

## 2. Fork-id rules (exact order; the SDKs mirror this list)

| # | Constant | Value |
|---:|---|---:|
| 1 | `consensus::MAX_COMMIT_CERT_SIGNERS` | 4,096 |
| 2 | `consensus::MAX_ROUND_AHEAD` | 1,000 |
| 3 | `consensus::MAX_ROUND_ADVANCE_PER_MESSAGE` | 1 |
| 4 | `consensus::MAX_SYNC_JUMPS_PER_ROUND` | 8 |
| 5 | `consensus::FROZEN_ROUND_TIMEOUT_BASE_MS` | 3,000 |
| 6 | `consensus::MICRO_COMMITTEE_MAX_SIZE` | 128 |
| 7 | `staking::DOWNTIME_MISS_THRESHOLD` | 42 |
| 8 | `staking::DOWNTIME_PENALTY_COOLDOWN` | 500 |
| 9 | `staking::JAIL_RELEASE_DELAY_HEIGHTS` | 4,000 |
| 10 | `staking::COMMISSION_EFFECT_DELAY_HEIGHTS` | 30,000 |
| 11 | `staking::COMMISSION_CHANGE_COOLDOWN_HEIGHTS` | 30,000 |
| 12 | `cn_vrf::EPOCH_LEN` | 30,000 |
| 13 | `cn_vrf::V3_SEGMENT_LEN` | 1,875 |
| 14 | `cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS` | 682 |
| 15 | `pq_registry::PQ_ROTATION_DELAY_HEIGHTS` | 30,000 |
| 16 | `mev_kem_registry::MEV_KEM_ROTATION_DELAY_HEIGHTS` | 30,000 |
| 17 | `mev_epoch::EPOCH_BLOCKS` | 500 |
| 18 | `mmr::MMR_EPOCH_BLOCKS` | 500 |
| 19 | `minroot_vdf::DEFAULT_VDF_STEPS_PER_EPOCH` | 3,000,000 |
| 20 | `consensus::PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT` | `u64::MAX` |

Entries 1–19 keep the ruleset-v2 order exactly. Entry 20 is new in v3: folding
the sentinel means activating proposal slashing necessarily moves the fork id.

**SDK pins:** `stellereum-sdk/src/protocol.rs` and `sdk-js/src/protocol.ts`
carry the same 20 rules, `CONSENSUS_RULESET_VERSION = 3`,
`DOMAIN_SET_VERSION = 2`, the V3 vote-domain fold, and
`FORK_ID_HEX = "0xb13baff4"`. `stellereum-sdk/tests/parity.rs`
(`protocol_identity_matches_the_node`) fails if this file, the node and the
SDKs ever disagree.

## 3. Proposal slashing: DISABLED (sentinel)

`consensus::PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT` is `u64::MAX`.
`verify_proposal_equivocation_evidence` fails closed while the sentinel is
unset: a block carries no SIGNED round, so a cross-round pair of honest
proposals at the same height (different bodies, one per round) is
indistinguishable from a double-propose. Slashing on it would burn an honest
proposer, and no slashing is strictly better than a false one.

The ready-to-enable rule
(`proposal_equivocation_offense_rule`: same shard AND same height AND same
round AND different block hash) is implemented and tested, but it stays
behind the sentinel until `round` is part of the SIGNED block identity. That
is a `Block` format change and requires its own coordinated rollout and a
fork-id move — which entry 20 guarantees by construction.

Offense evidence is also required to be same-shard:
`verify_proposal_equivocation_evidence` refuses a cross-shard pair, and
`staking::slash_equivocation_verified` independently refuses a cross-shard
vote pair (defence in depth) because one key may honestly sign per shard.

## 4. New genesis required

`FORK_ID` is part of `CHAIN_IDENTITY` and is exchanged in the control
handshake. A ruleset-v3 node refuses consensus with any v1/v2 peer. Existing
state cannot be migrated in place: run a new genesis with the v3 binary and
key material. Operators should expect the startup banner:

```text
[protocol] version 1.0 fork_id 0xb13baff4 capabilities 0x... ruleset_version 3
```

`version_info()` exposes `fork_id_hex = "0xb13baff4"`,
`consensus_ruleset_version = 3`, `domain_set_version = 2`.
