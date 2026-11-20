# Consensus ruleset v2 — 240 ms height calibration (new genesis)

> **SUPERSEDED by ruleset v6** (`docs/RULESET_V6.md`, `FORK_ID = 0x0f584a46`).
> This page is the historical v2 rationale and its fork-id pin (`0x3b768f7a`).
> All v2 rule values remain folded in v6; do not use v2 as the current ruleset.

**Status:** deliberate consensus change (ruleset v2). **Activation:** new
genesis; there is no in-place activation height. Old (ruleset v1) and new
(ruleset v2) binaries refuse consensus participation with each other because
`FORK_ID` changed (§Fork identity), so a mixed fleet fails closed at the
handshake instead of silently diverging.

**Tempo assumption:** one block = **240 ms**. Every window below is a height
count. Conversions use one rule:

```text
heights = ceil(duration_ms / 240)
wall_clock = heights * 240 ms
```

Ceiling is deliberate: a rescaled window is never shorter than its intent.

`CONSENSUS_RULESET_VERSION` is **2** (`stellereum/src/protocol.rs`).

---

## 1. Rescaled consensus windows

Old wall-clock values are also at 240 ms, to show how far the v1 (3 s-era)
heights had drifted.

| Constant | Old | Old @ 240 ms | New | New @ 240 ms | Rationale |
|---|---:|---:|---:|---:|---|
| `staking::DOWNTIME_MISS_THRESHOLD` | 10 | 2.4 s | **42** | **10.08 s** | Restore ~10 s outage tolerance; v1 slashed/jailed on ordinary WAN jitter. |
| `staking::DOWNTIME_PENALTY_COOLDOWN` | 100 | 24 s | **500** | **120 s (2 min)** | Bound repeat-slash drain over a multi-minute outage. Still < jail release. |
| `staking::JAIL_RELEASE_DELAY_HEIGHTS` | 1,000 | 4 min | **4,000** | **960 s (16 min)** | Keep a jailed validator out for a meaningful outage window. > penalty cooldown. |
| `staking::COMMISSION_EFFECT_DELAY_HEIGHTS` | 7,200 | 28.8 min | **30,000** | **7,200 s (2 h)** | Restore the delegator exit window; a raise cannot land before delegators can leave. |
| `staking::COMMISSION_CHANGE_COOLDOWN_HEIGHTS` | 7,200 | 28.8 min | **30,000** | **7,200 s (2 h)** | At most one effective commission change per exit window. |
| `staking::REENTRY_LIVENESS_WINDOW_HEIGHTS` | 10 (derived) | 2.4 s | **42 (derived)** | **10.08 s** | Derived from `DOWNTIME_MISS_THRESHOLD`; watch and slash windows stay identical by construction. |
| `pq_registry::PQ_ROTATION_DELAY_HEIGHTS` | 7,200 | 28.8 min | **30,000** | **7,200 s (2 h)** | PQ rotation announcement must be observable for a full 2 h before the key gains authority. Pinned equal to `EPOCH_LEN`. |
| `mev_kem_registry::MEV_KEM_ROTATION_DELAY_HEIGHTS` | 7,200 | 28.8 min | **30,000** | **7,200 s (2 h)** | Same exit-window philosophy for the MEV KEM key; pinned equal to the PQ delay. |
| `cn_vrf::EPOCH_LEN` | 7,200 | 28.8 min | **30,000** | **7,200 s (2 h)** | One PQ rotation window = one CN-VRF epoch. |
| `cn_vrf::V3_SEGMENT_LEN` | 450 | 108 s of slots | **1,875** | **450 s of slots** | Derived: `EPOCH_LEN / V3_SEGMENTS` (`16 × 1,875 = 30,000`). Compile-asserted. Worst-case reveal verification rises from 450 to 1,875 BLAKE3-XOF-48 calls (~4×, still microseconds). |
| `cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS` | 360 | 86.4 s | **682** | **163.68 s** | Derived from the measured MinRoot evaluation (§VDF), not by feel. |
| `mev_epoch::EPOCH_BLOCKS` | 128 | 30.72 s | **500** | **120 s (2 min)** | MEV epoch-key rotation stays a short, regular cadence. |
| `mmr::MMR_EPOCH_BLOCKS` | 128 | 30.72 s | **500** | **120 s (2 min)** | Must equal the MEV epoch (compile-asserted); one MMR root per MEV epoch. |
| `mev_epoch::ORDER_COMMITMENT_LOOKBACK` | 4 | 0.96 s | **50** | **12 s** | Node-local retention bound, not a consensus rule. 4 heights was ~12 s at 3 s blocks; at 240 ms it was under 1 s. |
| `minroot_vdf::DEFAULT_VDF_STEPS_PER_EPOCH` | 3,000,000 | — (not a height) | **3,000,000 (unchanged)** | §VDF | Fits comfortably; lowering it would weaken the time-asymmetry work factor, raising the lookahead was cheaper. |

No other value in the owned files is a height-duration window. In particular
`staking::UNBONDING_PERIOD_SECS` is already seconds (unchanged), the slash BPS
values are fractions, and `CONSENSUS_RULESET_VERSION`/`DOMAIN_SET_VERSION` are
versions.

### 1.1 Other height-ish constants: decisions

| Constant | Value | Decision |
|---|---:|---|
| `mev_epoch::MEV_RESHARE_DELTA_STAR_EPOCHS` | 2 | **Unchanged.** It counts epochs, not heights; with a 500-block epoch it becomes 4 min. The feature is inactive (`MEV_RESHARE_ACTIVATION_HEIGHT = u64::MAX`). |
| `mev_epoch::PQ_TRANSPORT_H_ACTIVATION_HEIGHT` | 10,000 | **Unchanged.** Activation/schedule metadata, not a duration; the PQ transport is active at every height. |
| `mev_epoch::MEV_RESHARE_ACTIVATION_HEIGHT` | `u64::MAX` | **Unchanged.** Activation gate (feature off). |
| `minroot_vdf::TEST_VDF_STEPS` | 64 | **Unchanged.** Test-only step count. |

---

## 2. VDF measurement and lookahead derivation

`DEFAULT_VDF_STEPS_PER_EPOCH = 3,000,000` is evaluated at `H_freeze`, and the
result must be ready before the epoch boundary. The measurement was taken with
the crate's release profile on one core (the evaluation itself is strictly
sequential):

```text
$ CARGO_BUILD_JOBS=2 cargo test --release --test zz_vdf_measure_temp \
      -- --nocapture --test-threads=1
VDF_MEASURE steps=50000    wall=366.357ms  rate=136479 steps/s
VDF_MEASURE steps=300000   wall=2023.360ms rate=148268 steps/s
VDF_MEASURE steps=3000000  wall=20455.259ms rate=146662 steps/s
```

Measurement host: AMD Ryzen 5 3600, rustc 1.91.1, release profile. The
300,000 → 3,000,000 scaling is linear (per-step cost is constant). The
measurement harness (`zz_vdf_measure_temp`) was a temporary test file, deleted
after the run; the numbers above are the pasted output.

Derivation (documented assumptions, not measurements of remote hosts):

* measured 3,000,000-step eval: **20.455 s** on this host;
* **4×** allowance for the weakest supported validator class (1-vCPU VPS,
  slower single-core than the measurement host);
* **2×** headroom for dispatch/scheduling on an otherwise busy validator;

```text
budget      = 20.455 s × 4 × 2 = 163.64 s
lookahead   = ceil(163.64 s / 0.24 s) = 682 blocks
lookahead   = 682 × 240 ms = 163.68 s
```

So the VDF has ~8× the measured evaluation time in the window, i.e. ~2× even
if the weakest validator is 4× slower than the measurement host. The lookahead
is only 2.27 % of a 30,000-block epoch, leaving a 29,318-block commit window
(~1 h 57 m) before `H_freeze`.

Trade-off considered: lowering `DEFAULT_VDF_STEPS_PER_EPOCH` would shrink the
lookahead but weakens the VDF's sequential work factor; raising the lookahead
costs only a small slice of the commit window. Keeping 3,000,000 steps and
raising the lookahead from 360 to 682 is the cheaper, safer option.

---

## 3. Fork identity (proof that old and new binaries refuse each other)

`FORK_ID` is a compile-time FNV-1a-32 fold over the chain id, the ruleset
version, the consensus wire/domain strings, and the rule constants now kept in
`protocol::FORK_ID_RULES`:

```text
consensus bound/round constants (v1 set)
staking height windows
cn_vrf EPOCH_LEN / V3_SEGMENT_LEN / V3_COMMIT_LOOKAHEAD_BLOCKS
pq_registry / mev_kem_registry rotation delays
mev_epoch / mmr epoch lengths
minroot_vdf DEFAULT_VDF_STEPS_PER_EPOCH
```

| Ruleset | `CONSENSUS_RULESET_VERSION` | `FORK_ID` |
|---|---:|---|
| v1 (historical, six bound/round constants + V1 equivocation domains) | 1 | `0xc5ddb707` |
| **v2 (this change, 19 rules + V2 equivocation domains)** | **2** | **`0x3b768f7a`** |

The value is not arbitrary: both shipped SDKs already pin it
(`stellereum-sdk/src/protocol.rs`, `sdk-js/src/protocol.ts`). The node's
`FORK_ID_RULES` is the same 19-entry list, in the same order, and the node's
`EQUIVOCATION_OFFENSE_DOMAIN` / `PROPOSAL_EQUIVOCATION_OFFENSE_DOMAIN` are the
`V2` strings the SDK folds. A node-side regression test
(`fork_id_v2_is_pinned_and_matches_the_sdk_guard`) asserts the exact value and
the exact list order, and
`fork_id_v2_differs_from_the_historical_v1` recreates the historical V1 fold
and proves the ids differ. The v2 pin and the v1-inequality proof live in
`stellereum/tests/protocol_negotiation_tests.rs`.

---

## 4. Activation note

* This is a **new genesis**. There is no height at which an old node flips
  behavior: the ruleset version and the constants are compiled in.
* A ruleset-v1 binary and a ruleset-v2 binary derive different `FORK_ID`
  values and **refuse consensus participation with each other** (loudly);
  DHT/blob service remains available per the existing negotiation policy.
* Any persisted ruleset-v1 chain data is not valid under v2. Operators must
  start from a v2 genesis / fresh data directory; restoring a v1 data
  directory does not make the old chain valid under v2 rules.

---

## 5. Documentation supersession / owned elsewhere

* `docs/LOGIC_BUG_SWEEP.md` §7.1 and `docs/PQ_CN_VRF_SPEC.md` /
  `docs/CNVRF_V3_ROLLOUT.md` still quote the v1 numbers and are historical
  analyses; this file is authoritative for ruleset v2.
* `governance::GOV_TIMELOCK_HEIGHTS` (`stellereum/src/governance.rs`) is
  **owned by another scope** and was not changed here. It is still `7,200`
  heights (~28.8 min at 240 ms); the intended ruleset-v2 target is ~6 h
  (`90,000` heights) and must be applied by that owner, together with its
  commission-window equivalence test.
* Runtime/state-engine tests that hard-code v1 epoch boundaries
  (`6840`, `7200`, `14040`, `14400`) are in `runtime/**` (owned by another
  scope); they must be re-derived from `cn_vrf::EPOCH_LEN` and
  `V3_COMMIT_LOOKAHEAD_BLOCKS` by that owner.
