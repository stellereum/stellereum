# Consensus ruleset v4 — signed block round, deterministic timestamp bound, fork id `0x611600c9` (new genesis)

> **SUPERSEDED by ruleset v6** (`docs/RULESET_V6.md`, `FORK_ID = 0x0f584a46`).
> The v4 signed-round, timestamp-bound and proposal-slashing rules are still
> current; the v4 fork id and its 21-rule pin are historical. V5 appended the
> chain-wide supply rules (22–23) and v6 changed lock identity.

**Status:** deliberate consensus change (ruleset v4). **Activation:** new
genesis; there is no in-place activation height. Ruleset v3 and ruleset v4
binaries refuse consensus participation with each other because `FORK_ID`
changed, so a mixed fleet fails closed at the handshake instead of silently
diverging.

- `CONSENSUS_RULESET_VERSION = 4` (`stellereum/src/protocol.rs`)
- `DOMAIN_SET_VERSION = 2` (unchanged)
- `FORK_ID = 0x611600c9` (was `0xb13baff4` under ruleset v3,
  `0x3b768f7a` under ruleset v2, `0xc5ddb707` under the historical v1)
- `MAX_BLOCK_TIMESTAMP_DRIFT_MS = 3_600_000` (1 hour)
- `PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT = 0` (ACTIVE)

Every ruleset-v2/v3 rule value is still folded, in the same order. The new
values are appended (rules 20 and 21), so the historical ids remain
reproducible by tests.

---

## 1. The block now commits a SIGNED round

`Block` gained `pub round: u32`. It is mixed into `Block::compute_hash` under
the domain tag `ROUND001` whenever it is non-zero, so the proposer signature
and every vote/QC over the block hash commit to the round:

```text
STELLEREUM_BLOCK_V3 ‖ chain_id(8, BE) ‖ shard_id(4, BE) ‖ height(8, BE)
    ‖ [ "ROUND001"(8) ‖ round(4, BE) ]          (only when round != 0)
    ‖ prev_hash(32) ‖ state_root(32) ‖ ...      (unchanged from v3)
```

The zero-skip follows the same versioning rule as the order, shard-head,
epoch-key, last-QC and MMR commitments: **round 0 is the canonical default and
the only value a pre-v4 body can mean**, so a round-0 block keeps the exact
pre-v4 hash, signatures and QCs. Any non-zero round is a new, domain-separated
identity. Round 0 does not create a second encoding of a non-zero round; the
default is itself the commitment rule.

### Why the round is signed (the false-slash gap it closes)

The round used to travel only in the UNSIGNED `ConsensusMsg::Proposal`
envelope. A scheduled proposer that signs two different bodies at the same
height leaves no vote pair behind (the vote-equivocation path is inapplicable
by construction). Proposal slashing therefore had to stay disabled: an honest
view change produces A in round r and B in r+1 at the same height, and without
a signed round that pair is byte-for-byte indistinguishable from a
double-propose. Slashing it would burn an honest proposer — strictly worse
than not slashing.

With the round inside the signed hash:

- `ProposalEquivocationEvidence.round` must equal **both** blocks' signed
  `round`;
- `proposal_equivocation_offense_rule` requires
  `same shard && same height && same ROUND && different hash`;
- the wired verifier (`verify_proposal_equivocation_evidence`) no longer
  refuses unconditionally: it verifies the pair and activates at height 0.

Validators also require `block.round` to be legal for the proposal round on
**both** paths:

- admission: `on_proposal` / `validate_proposal` use
  `accepts_block_round`, i.e. `block.round <= self.hc.round` — exact equality
  in the normal case, and an EARLIER signed round for the lock-rescue /
  one-round-lag re-proposal (a FUTURE round is refused);
- adopt: `block.round <= certificate.round` beside the proposer-schedule
  check. A body produced for one round can never be adopted under a quorum
  harvested for another.

> Historical wording: the first v4 cut required strict equality
> (`block.round == hc.round`) on admission. That rejected a re-served locked
> body signed at an earlier round and was relaxed to `<=` on the current tree;
> the signed-round identity and the adopt bound are unchanged.

### Serde / bincode

The field is the **trailing** block field, with `serde(default)` and the
same local-store tolerance as every previous trailing commitment
(`de_round`): a pre-v4 body persisted before this field ends its byte stream
one field early and decodes as round 0 under
`with_legacy_block_tolerance`. The **wire** path stays strict and fails
closed on the missing bytes; a mixed-version fleet never "verifies the parts
it understands". This is a hard fork: new genesis required (§4).

## 2. Deterministic block-timestamp bound (S8)

The proposer stamps `Block::timestamp`; validators gate it in
`runtime::consensus_step::check_block_timestamp` on the proposal AND adopt
paths. The rule is a **pure function of (parent, block)**, with no wall-clock
read:

```text
block.height > 0  =>  parent.timestamp <= block.timestamp
                      <= parent.timestamp + MAX_BLOCK_TIMESTAMP_DRIFT_MS / 1000
```

- `MAX_BLOCK_TIMESTAMP_DRIFT_MS = 3_600_000` (1 hour) lives in
  `protocol.rs` and is folded as fork rule 21.
- Block timestamps are `u64` **seconds**; the rule is stated in milliseconds
  because the ~240 ms tempo is sub-second. One hour is ~15,000 tempo slots: the
  envelope this repo's own suites use for honest clock skew, retries and
  catch-up (single-step jumps of ~1000s), while still refusing a validator that
  tries to poison timestamp-driven rules (session expiry, unbonding maturity,
  order stamps) for days or years.
- `runtime::MAX_TIMESTAMP_JUMP_SECS = 3_600` mirrors the same bound for the
  proposer clamp and is pinned equal by tests.
- The honest proposer clamps its clock into the SAME window
  (`mev_sync::propose`), so a fast local clock cannot build a body its peers
  must refuse.
- Height 0 (genesis) keeps its fixed timestamp: it has no parent and the
  parent-relative rule does not apply. Height 1 whose parent is the
  zero-genesis anchor is exempt from the FORWARD bound (the anchor carries no
  timestamp), while monotonicity still holds; a missing parent timestamp fails
  closed.

## 3. Fork-id rules (exact order; the SDKs mirror this list)

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
| 20 | `consensus::PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT` | 0 (active) |
| 21 | `protocol::MAX_BLOCK_TIMESTAMP_DRIFT_MS` | 3,600,000 |

Entries 1–19 keep the v2/v3 order exactly. Entry 20 changes value from the v3
sentinel (`u64::MAX`) to `0`, activating proposal slashing. Entry 21 is new.

**SDK pins:** `stellereum-sdk/src/protocol.rs`, `stellereum-sdk/src/constants.rs`
and `sdk-js/src/protocol.ts` carry the same 21 rules,
`CONSENSUS_RULESET_VERSION = 4`, `DOMAIN_SET_VERSION = 2`, the unchanged domain
set, and `FORK_ID_HEX = "0x611600c9"`.
`stellereum-sdk/tests/parity.rs` (`protocol_identity_matches_the_node`) and
`stellereum/tests/protocol_negotiation_tests.rs` fail if the node, both SDKs
and this document ever disagree.

## 4. New genesis required

`FORK_ID` is part of `CHAIN_IDENTITY` and is exchanged in the control
handshake. A ruleset-v4 node refuses consensus with any v1/v2/v3 peer.
Existing state cannot be migrated in place: run a new genesis with the v4
binary and key material. Operators should expect the startup banner:

```text
[protocol] version 1.0 fork_id 0x611600c9 capabilities 0x... ruleset_version 4
```

`version_info()` exposes `fork_id_hex = "0x611600c9"`,
`consensus_ruleset_version = 4`, `domain_set_version = 2`.

## 5. Fixtures

Every full `Block { .. }` literal now spells `round` explicitly (the compiler
enforces it); fixtures that build through `Block::new_for_test` or
`Default::default()` get round 0 automatically. Consensus/proposal fixtures
that exercise a specific round set it before signing, because the round is
inside the hash. Adopt fixtures set `block.round == certificate.round`.
