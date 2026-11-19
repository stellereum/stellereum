# CN-VRF v3 — activation and rollout checklist

Scope: the CN-VRF v3 work merged in `1de815a99` ("CN-VRF v3: segmented BLAKE3 chain,
MinRoot VDF, on-chain state and runtime wiring") and `6e6384940` ("Wave 1a: convert every
stale Ed25519 fixture to FULL-PQ"). The gate is **OFF** at the snapshot: the activation
constant is `u64::MAX` (`stellereum/src/consensus/sortition.rs:507`).

> **SUPERSEDED FOR CONSTANTS (still valid for the checklist).** This document is
> a snapshot at `HEAD = 6e6384940` under ruleset **v1**. Ruleset **v2**
> (`docs/RULESET_V2.md` §1) rescaled every height-derived constant and ruleset
> **v3** (`docs/RULESET_V3.md` §2) inherited those values into fork
> `0xb13baff4`. The gate itself is still `u64::MAX` at HEAD `9832e97a9`
> (`stellereum/src/consensus/sortition.rs:664`); only the line numbers and the
> height values moved. **Do not copy the numbers from this page.**
>
> | constant | this snapshot (v1) | current (ruleset v3) |
> |---|---:|---:|
> | `cn_vrf::EPOCH_LEN` / `CNVRF_V3_EPOCH_LEN` | 7,200 | **30,000** |
> | `V3_SEGMENT_LEN` | 450 | **1,875** |
> | `V3_COMMIT_LOOKAHEAD_BLOCKS` | 360 | **682** |
> | `JAIL_RELEASE_DELAY_HEIGHTS` | 1,000 | **4,000** |
> | `PQ_ROTATION_DELAY_HEIGHTS` | 7,200 | **30,000** |
> | `COMMISSION_EFFECT_DELAY_HEIGHTS` | 7,200 | **30,000** |
> | `DOWNTIME_MISS_THRESHOLD` | 10 | **42** |
> | `MEV_EPOCH_BLOCKS` / `MMR_EPOCH_BLOCKS` | 128 | **500** |
>
> `CNVRF_V3_ACTIVATION_HEIGHT` and `BEACON_DRAW_ACTIVATION_HEIGHT` are still
> `u64::MAX` (off). The rollout steps, the commit/reveal flow and the
> abort-slash conditions below are unchanged.

Every constant and behaviour below was read from the files cited next to it. Wall-clock
numbers that I did not measure on the target hosts are marked **UNVERIFIED — must be measured**.

**Snapshot:** `HEAD = 6e6384940b955b1277e9cb5646b7d0e6769e7468`, working tree dirty (the
classical-excision edits described in `docs/CLASSICAL_EXCISION_STATUS.md` are uncommitted and
were landing while this was written). Re-run the commands in §7 before acting.

---

## 1. What is actually merged

| component | evidence |
|---|---|
| 48-byte, 16-segment reverse BLAKE3 hash chain over a 7,200-block epoch | `cn_vrf.rs:1013-1021` (`V3_LINK_LEN=48`, `V3_SEGMENTS=16`, `V3_SEGMENT_LEN=450`; compile-time `16*450 == 7200` at `:1021`) |
| commit carrier = 16 anchors + Falcon-512 signature | `cn_vrf.rs:1025` (`COMMIT_CARRIER_V3_LEN = 32 + 8 + 16*48 + 666 = 1474` bytes), `:1397-1417` (commit), `:1422-1443` (verify) |
| reveal verified in ≤ 450 BLAKE3 steps | `cn_vrf.rs:1463-1497` |
| MinRoot VDF epoch beacon | `minroot_vdf.rs:37-38`, `:312-347` (`eval`), `:354-404` (`verify`) |
| on-chain state transition | `state_engine/apply.rs:2609-2618` (gate), `:2635-2859` (`apply_cnvrf_v3`) |
| runtime wiring (payload, epoch hooks, custody) | `runtime/anchors.rs:565-607`, `:659-752`, `:363-454` |
| sortition / proposer selection by beacon | `consensus/types.rs:909-934`, `:1451-1462`; `consensus/sortition.rs:505-590` |
| abort-slash for a committed proposer that withholds its reveal | `staking.rs:3348-3400` |

### Constants you must not guess

| constant | value | file:line |
|---|---|---|
| `CNVRF_V3_ACTIVATION_HEIGHT` | **`u64::MAX`** (never) | `consensus/sortition.rs:507` |
| `CNVRF_V3_EPOCH_LEN` | `7_200` (asserted `== cn_vrf::EPOCH_LEN`) | `consensus/sortition.rs:511-513` |
| `cn_vrf::EPOCH_LEN` | `7_200` | `cn_vrf.rs:65` |
| `V3_COMMIT_LOOKAHEAD_BLOCKS` | `360` (5 % of the epoch) | `cn_vrf.rs:1019` |
| `V3_LINK_LEN` / `V3_SEGMENTS` / `V3_SEGMENT_LEN` | `48` / `16` / `450` | `cn_vrf.rs:1013-1017` |
| `COMMIT_CARRIER_V3_LEN` | `1474` (from the formula at `:1025`) | `cn_vrf.rs:1025` |
| `DEFAULT_VDF_STEPS_PER_EPOCH` | `3_000_000` | `minroot_vdf.rs:38` |
| `MAX_CNVRF_V3_COMMITS_PER_BLOCK` | `256` | `runtime/mod.rs:470` |
| `MAX_PENDING_CNVRF_V3_COMMITS` | `1024` | `runtime/mod.rs:468` |
| `CNVRF_ABORT_THRESHOLD` | `3` misses | `staking.rs:357` |
| `CNVRF_ABORT_SLASH_BPS` | `100` (= 1 %, over `BPS_DENOMINATOR = 10_000`) | `staking.rs:353`, `:301` |
| `CNVRF_ABORT_RECOVERY_STREAK` | `20` valid reveals to remove one miss | `staking.rs:363` |
| `JAIL_RELEASE_DELAY_HEIGHTS` | `1_000` | `staking.rs:315`, applied at `:3465-3481` |
| `BEACON_DRAW_ACTIVATION_HEIGHT` (older XMSS draw) | `u64::MAX` — **leave it alone** | `consensus/sortition.rs:419` |

---

## 2. The exact knob to flip

There is **one** production knob and **no environment override**:

```
stellereum/src/consensus/sortition.rs:505-507

/// Activation height of CN-VRF v3 sortition and proposer beacon selection:
/// `u64::MAX` = never (GatedOff sentinel until Sub-wave B + audit/rollout).
pub const CNVRF_V3_ACTIVATION_HEIGHT: u64 = u64::MAX;
```

* Flip it to the chosen height `H` and rebuild **all** validator and full-node binaries from the
  same commit. Every gate reads this constant through `cnvrf_v3_active_at`
  (`sortition.rs:523-531`), including the state engine (`state_engine/accounts.rs:1257-1271`) and
  the runtime (`runtime/anchors.rs:159-176`).
* The only other way to move the activation is a **test/debug-only override**
  `set_cnvrf_v3_activation_height_for_tests` (`runtime/anchors.rs:134-139`,
  `state_engine/accounts.rs:1250-1254`), compiled under
  `#[cfg(any(test, debug_assertions))]`. It does not exist in a release build. Do not ship a
  debug build to production to get an override.
* `CNVRF_V3_ACTIVATION_HEIGHT` is also listed in the public activation schedule
  (`chain_spec.rs:134-138`) and in a consistency test (`chain_spec.rs:243`). A flip is therefore
  visible in `stell_getActivationSchedule`; that test compares the schedule entry against the
  same module constant, so it stays green automatically.

**Choose `H` as an exact multiple of 7,200.** Reason, from the code:

* `active_epoch_beacon` returns a deterministic bootstrap beacon for an epoch whose `H_freeze`
  (`epoch*7200 - 360`) happened **before** activation (`anchors.rs:200-213`). With `H = E*7200`,
  epoch `E`'s `H_freeze = H - 360 < H`, so epoch `E` is bootstrapped deterministically on every
  node and needs no VDF.
* Any other `H` can make the *first* active epoch's `H_freeze` fall at/after activation. That
  epoch then has neither a finalized beacon nor a VDF-ready one, `active_epoch_beacon` returns
  `None`, and proposer selection plus QC verification fail closed (`types.rs:928-931`,
  `:1449-1462`) — the chain stops instead of degrading.

---

## 3. Preconditions

### 3.1 Network / upgrade shape

* **Coordinated upgrade, not a mixed deployment.** Activation changes proposer selection
  (`types.rs:909-934`), block payload (`sharding/block.rs:438-447`), and state transition
  (`apply.rs:2609-2618`). A node on the old binary computes different proposers for the same
  height and rejects the new payload, so a mixed set splits or stalls.
* **Fresh genesis is not required for decoding.** `cnvrf_v3` is a trailing, `serde(default)`
  field with a tolerant reader (`sharding/block.rs:442-447`, `:651-676`); pre-activation blocks
  decode with `None` and keep their historical hash (`block.rs:115-116`, `:947-948`). A
  same-genesis coordinated upgrade is therefore viable.
* **A fresh genesis is required if you change validator ids or the epoch/beacon domain at the
  same time.** The CN-VRF records are keyed by `ValidatorId` and epoch (`cn_vrf.rs:107`,
  `:1599`), and the epoch seed binds `chain_id` (`cn_vrf.rs:1707-1724`), which is folded into the
  state commitment domain (`apply.rs:2843-2845`). Any such change moves the state root.
* **The activation epoch is a warm-up epoch.** A commitment for epoch `N` must be made before
  `N*7200 - 360`, i.e. during epoch `N-1` (`cn_vrf.rs:1569-1594`). At activation there is no epoch
  `E-1` under the gate, so epoch `E` has no commitments: every `apply_slot_reveal` returns
  `AbsentNoCommit` (`cn_vrf.rs:1624-1629`), nothing is slashed, and the rolling mix stays zero. The
  first epoch that can carry reveals is `E+1`. The module records this as O9 /
  `first_usable_epoch` (`cn_vrf.rs:606-612`), but that helper has **no runtime caller**
  (`rg -n "first_usable_epoch" stellereum/src/` finds only its definition and a doc reference), so
  the warm-up is a convention you must expect, not something the node enforces.
* **Do not also flip `BEACON_DRAW_ACTIVATION_HEIGHT`** (`sortition.rs:419`). It is a different,
  older draw; CN-VRF v3 replaces the proposer draw through `cnvrf_v3_active_at`, and the manifest
  keeps the old draw off at every reachable height (`sortition.rs:403-409`).

### 3.2 Every validator must be able to compute the VDF

The beacon used to *choose the proposer* and to *verify a QC* is read from **local** state —
finalized beacons, then locally computed `ready_vdf_beacons`, then the bootstrap fallback
(`anchors.rs:188-214`). It is **not** taken from the block being verified. Therefore, for every
epoch past the bootstrap one, **each validator** (not only the proposer) must have completed the
epoch's MinRoot evaluation before the boundary, or it will see `None` and refuse to propose or
verify (`types.rs:928-931`, `:1449-1462`).

The evaluation is dispatched at `H_freeze` (360 blocks before the boundary), on a
`spawn_blocking` worker so it cannot stall the async consensus tick
(`anchors.rs:696-735`, `runtime/lanes.rs:584-596`), and is polled on every finalized-block
advance and at the driver's poll points (`anchors.rs:659-664`, `node/consensus_driver.rs:1791`,
`:3288`).

### 3.3 VDF step count must be calibrated on the real hosts

`cnvrf_v3_vdf_steps` defaults to `DEFAULT_VDF_STEPS_PER_EPOCH = 3_000_000`
(`anchors.rs:108`, `minroot_vdf.rs:38`). The number is a **source comment**, not a measurement:
"~21.8 s 1-core eval, ~156 ms 1-core verify at ~137.6k / ~19.3M steps/s" (`minroot_vdf.rs:37`).
There is no environment knob and the node driver never calls `set_cnvrf_v3_vdf_steps`
(`anchors.rs:141-150` is a public setter, not wired in `node/`).

* **UNVERIFIED — must be measured**: on the actual 1-vCPU hosts, does 3,000,000 steps finish
  well inside the 360-block window? Measure it with §7's bench command on each host class, then
  multiply `steps / steps_per_sec` by the measured block time.
* If it does not fit, changing the step count is a **network-wide code change**, because proposal
  validation requires the carried proof's steps to equal the local constant
  (`anchors.rs:921-926`). The state transition itself verifies with the proof's own `steps`
  (`apply.rs:2808-2811`), so an individual node cannot silently use a different value and be
  correct — it would simply be unable to build a valid proposal.
* Budget for the async cost: the eval runs on a blocking thread, but on a 1-vCPU box it competes
  with the consensus tick for the only core. Measure under load, not on an idle box.

### 3.4 Custody directory and operator secrets

* The node configures custody only when the gate is already live at its height:
  `STELL_CNVRF_V3_DIR`, else `data/cnvrf_v3` (`node/consensus_driver.rs:190-203`), then runs the
  boot self-check (`anchors.rs:363-454`).
* Per-epoch secret path: `<dir>/cnvrf_v3_epoch_<epoch>_<first 8 bytes of id in hex>.secret`
  (`anchors.rs:278-285`). Written as `enc2:` (Argon2id + XChaCha20-Poly1305) with `0600`, atomic
  replace, and symlink refusal (`cn_vrf.rs:1735-1771`, `:1778-1815`).
* **Write-ahead ordering matters**: the secret is persisted *before* the commit is signed or
  queued; a persistence failure refuses to sign (`anchors.rs:500-525`). A validator that signs
  first and loses the file can never reveal for that epoch.
* **Back up the custody directory plus the passphrase before the first activated epoch.**
  Without the matching secret, the boot check disables local reveal/propose for that epoch
  (`anchors.rs:385-421`) and the validator accrues misses.
* Passphrase variables come from the node-keys policy: `STELL_KEY_PASSPHRASE`,
  `STELL_NODE_PASSPHRASE`, `INFNODE_KEY_PASSPHRASE` (`node_keys.rs:28-33`). Losing the
  passphrase is equivalent to losing the secret: `load_cnvrf_v3_secret` hard-fails
  (`cn_vrf.rs:1791-1797`).

### 3.5 Chain id must match the custody chain id

`consensus_driver.rs:201` configures custody with `stellereum::zkml::DEFAULT_CHAIN_ID` (`5757`,
`zkml.rs:191`), while `apply_cnvrf_v3` admits commits under `self.chain_id` (`apply.rs:2715`).
If a deployment boots the state engine with a different chain id, every commit verifies under one
chain id and is admitted under another — commits are ignored and the epoch has no commitment.
**Precondition: run the CN-VRF chain on chain id 5757**, or change the driver to pass the state
engine's chain id before activating. There is no config knob for this today.

### 3.6 Monitoring

There are **no CN-VRF metrics** in `stellereum/src/metrics.rs` (verified: `rg -n "cnvrf"
stellereum/src/metrics.rs` returns nothing). Monitoring must key on logs until counters are added:

| signal | where |
|---|---|
| VDF lane returned nothing / channel closed | `anchors.rs:243-257` |
| secret file missing for an on-chain commitment | `anchors.rs:386-393` |
| on-disk secret does not match commit anchors | `anchors.rs:413-421` |
| cannot load the encrypted secret | `anchors.rs:423-432` |
| no custody dir but a commitment exists | `anchors.rs:434-441` |
| write-ahead persistence failed, refusing to sign | `anchors.rs:515-524` |
| boundary block omits / mis-names / mis-verifies the beacon | `anchors.rs:909-954` |
| commit rejected / no PQ key / bad scheme (apply) | `apply.rs:2684-2720` |
| invalid or unexpected reveal ignored (apply) | `apply.rs:2762-2775` |
| VDF proof fails / seed mismatch (apply) | `apply.rs:2815-2826` |
| abort slash applied or skipped | `staking.rs:3373-3386`; skip path `apply.rs:2751-2757` |

Alerting recommendation (not implemented here): alert on "epoch disabled" lines, on any
`epoch_vdf` rejection, and on `pending_cnvrf_v3_commits` never draining. The getters exist
(`anchors.rs:263-276`) but **have no caller outside `anchors.rs`**, so they are not on the RPC
surface.

---

## 4. Failure modes the code already fails closed on

| failure | where it is refused | effect |
|---|---|---|
| missing beacon at an epoch boundary | proposal: required and checked (`anchors.rs:907-914`); state: proof re-verified (`apply.rs:2808-2819`) | block is rejected; if no node has a beacon, no valid boundary block can be built |
| beacon names the wrong epoch | proposal: `anchors.rs:915-920`; committee draw returns empty (`sortition.rs:582-584`); proposer selection returns `None` (`types.rs:928-931`) | no proposer / no committee — halt rather than a wrong proposer |
| beacon for the wrong chain id / freeze input | seed recomputed and compared (`anchors.rs:933-948`, `apply.rs:2795-2806`) | beacon not recorded; warning |
| beacon with non-agreed step count | `anchors.rs:921-926` | proposal rejected |
| wrong-epoch or stale commit | `cn_vrf.rs:1581-1587` (`StaleOrCurrent` / `TooFarAhead`); proposal mirror `anchors.rs:852-854` | commit ignored/rejected; first valid one wins |
| commit past the freeze cutoff (`epoch*7200 - 360`) | `cn_vrf.rs:1588-1594`; proposal mirror `anchors.rs:855-861` | commit rejected |
| duplicate commit | `cn_vrf.rs:1598-1601` (`IgnoredDuplicate`, first-committed-wins) | no state change |
| invalid commit signature | `cn_vrf.rs:1427-1442` (length, all-zero sig, Falcon verify) | commit rejected |
| reveal that does not walk the chain | `cn_vrf.rs:1489-1495` → `InvalidReveal` (`:1654`); proposal rejects (`anchors.rs:890-894`) | block rejected before apply |
| stale or replayed reveal | `cn_vrf.rs:1477-1479` | `InvalidReveal` |
| reveal outside the epoch | `cn_vrf.rs:1474-1476` | `InvalidReveal` |
| reveal with no commitment | `cn_vrf.rs:1624-1629` → `UnexpectedReveal`; proposal rejects (`anchors.rs:896-900`) | block rejected |
| committed proposer omits the reveal | `cn_vrf.rs:1630-1632` → `CommittedMissingReveal`; accepted by proposal on purpose (`anchors.rs:882-889`) | charged on-chain: 3 misses → 1 % slash + 1,000-block jail (`staking.rs:3365-3386`, `:3454-3481`) |
| on-disk secret does not match the committed anchors | `cn_vrf.rs:1819-1826` compared at boot (`anchors.rs:396-421`) | local reveal/propose disabled for the epoch |
| commit from a validator with no active PQ key | `apply.rs:2691-2714` | commit ignored with a warning |
| VDF proof fails verification | `minroot_vdf.rs:354-404`; applied at `apply.rs:2808-2819` | beacon not recorded |

Deliberate non-failures (so an operator does not mistake them for bugs):

* `InvalidReveal` / `UnexpectedReveal` in **apply** are logged and ignored, because the proposal
  path already rejected them (`apply.rs:2762-2775`). Apply is the deterministic mirror.
* A missing reveal by a *committed* proposer must not reject the block, otherwise the offender
  escapes by never proposing again (`anchors.rs:882-886`).

---

## 5. Rollback plan

Rollback is **not** a runtime switch. Reverting the constant changes what the node puts in a
block and what it commits to in state:

* the payload is mixed into the block hash only when `Some` (`sharding/block.rs:947-948`), so
  post-activation blocks would re-hash differently under `cnvrf_v3 == None`;
* `apply_cnvrf_v3` bumps the state-commitment domain generation on every change
  (`apply.rs:2834-2845`), so the state root domain differs from the pre-activation chain.

Therefore:

1. **Pre-stage the rollback snapshot.** Take a full node snapshot (state + keys + CN-VRF custody
   dir) at `H - K` for a comfortable `K` (at least one epoch, 7,200 blocks, so the snapshot's
   commitments and secrets are consistent). Keep the pre-activation binary alongside it.
2. **Abort criteria** (any one): a boundary block cannot be produced or verified; consecutive
   "epoch disabled" lines on more than a threshold of validators; `epoch_vdf` rejection at every
   attempt; commit queue not draining across an `H_freeze`.
3. **Rollback = restore + redeploy**, on every validator, not a rolling flip:
   restore the pre-activation snapshot, redeploy the pre-activation binary (constant `u64::MAX`),
   and restart the network from that snapshot. A rolling per-node flip forks, because the two
   binaries compute different block hashes for the same height.
4. **Forward-only alternative** if the snapshot is stale: leave the constant live and repair the
   cause (usually missing custody secret or a VDF that did not finish). The fail-closed paths in
   §4 all stop the chain rather than corrupt it, so a stalled height is recoverable without a
   fork.
5. **Do not** delete the custody directory during a rollback. The per-epoch secrets are only
   useful for the epoch they were generated for, but a re-activation at a later epoch reuses the
   file naming scheme (`anchors.rs:278-285`) and the boot check will compare them against any
   on-chain record that still exists.

---

## 6. Operator runbook (ordered)

1. Pick `H = E * 7200` strictly greater than the current height plus one full epoch of lead time.
2. Measure VDF throughput on each host class (§7) and confirm 3,000,000 steps fit in the
   360-block window with margin. Record the numbers in the change ticket.
3. Create the custody directory on every validator, owned by the node user, mode `0700`; confirm
   the passphrase is present in the unit's environment file. Set `STELL_CNVRF_V3_DIR` if the
   default `data/cnvrf_v3` is not on the node's persistent volume.
4. Back up keys + custody dir + passphrase to the off-host location, and run a restore drill.
5. Flip `CNVRF_V3_ACTIVATION_HEIGHT` to `H`, rebuild, and deploy **all** validator and full-node
   binaries before `H - 7200` so the commit window has a full epoch.
6. Between deployment and `H`, watch for "disabling local reveal/propose" lines on any validator.
7. At `H`: confirm epoch `E` uses the deterministic bootstrap beacon and expect **no reveals** in
   it (warm-up epoch, see §3.1). Then confirm the first `H_freeze` at `H + 6840` dispatches VDF
   work and the beacon becomes ready before `H + 7200`; reveals and abort-slash accounting start in
   epoch `E+1`.
8. After the first boundary: confirm the rolling mix changes each epoch, and that an abort slash
   fires only for a validator that is genuinely down (not one that merely lost its secret and was
   already disabled — a disabled validator stops proposing, so it will look like downtime).

---

## 7. Test checklist (commands)

Run from `stellereum/` unless stated.

```bash
# 1. The dedicated CN-VRF suite (192 matching lines in tests/cn_vrf_tests.rs)
cargo test --test cn_vrf_tests --no-fail-fast

# 2. v3 unit tests inside the library
cargo test --lib cnvrf --no-fail-fast

# 3. Runtime integration (activation schedule + commit payload rejection)
cargo test --lib runtime::tests::cnvrf --no-fail-fast

# 4. MinRoot VDF round-trip / tamper rejection
cargo test --lib minroot_vdf --no-fail-fast

# 5. Measure eval/verify throughput ON THE TARGET HOST (release, prints steps/s)
cargo test --release --lib bench_eval_vs_verify_asymmetry -- --nocapture

# 6. Activation-schedule pins (CNVRF / PQ transport / PQ classical cutoffs)
cargo test --lib chain_spec --no-fail-fast

# 7. State-root completeness with CN-VRF state in the picture
cargo test --test state_root_completeness_tests --no-fail-fast

# 8. Consensus liveness under the 4-node sim harness
cargo test --test consensus_liveness_harness --no-fail-fast

# 9. Full mandatory gate (clippy -D warnings, fmt, all tests, sim)
cd .. && ./scripts/verify_testnet_ideal.sh
```

Notes:

* Command 5 is the only one that produces a number you can calibrate with. Run it under the same
  CPU quota as production (`taskset`/`cpuset`) rather than on an idle build host.
* Command 9 is currently **red** for reasons unrelated to CN-VRF: the in-flight classical
  excision leaves the library test target uncompilable. See
  `docs/CLASSICAL_EXCISION_STATUS.md`. Do not read a red gate as a CN-VRF failure without
  checking which target failed.
* The `--release` in command 5 matters: the test uses 50,000 steps in release and 1,000 in debug
  (`minroot_vdf.rs:924-929`), and debug throughput is not representative.

---

## 8. Numbers that are recommendations, not measurements

| item | current value | status |
|---|---|---|
| MinRoot steps per epoch | `3_000_000` (`minroot_vdf.rs:38`) | **UNVERIFIED — must be measured** on the 1-vCPU hosts. The "~21.8 s / ~156 ms" figures are a source comment, not a run in this environment. |
| Reveal verification cost | ≤ `450` BLAKE3 steps (`cn_vrf.rs:1463-1465`) | bound is code-verified; wall-clock is **UNVERIFIED** |
| Commit carrier size | `1474` bytes (`cn_vrf.rs:1025`) | arithmetic from the constant, verified |
| Blocks of lead time at `H_freeze` | `360` (`cn_vrf.rs:1019`) | constant verified; whether 360 blocks is enough wall-clock depends on the measured block time — **UNVERIFIED** |
| Abort-slash economics (1 %, 3 misses, 1,000-block jail) | `staking.rs:353-363`, `:315` | constants verified; whether they are the desired policy is a product decision, not a measurement |
| Alert thresholds for "epoch disabled" | none exist | **UNVERIFIED — no metrics today**; recommend adding counters before activation |

---

## Appendix — commands used

```
$ rg -n "pub const CNVRF_V3_ACTIVATION_HEIGHT|pub const CNVRF_V3_EPOCH_LEN|pub fn cnvrf_v3_active_at" stellereum/src/consensus/sortition.rs
507:pub const CNVRF_V3_ACTIVATION_HEIGHT: u64 = u64::MAX;
511:pub const CNVRF_V3_EPOCH_LEN: u64 = 7_200;
523:pub fn cnvrf_v3_active_at(height: Height) -> bool {
```

```
$ rg -n "pub const (EPOCH_LEN|V3_LINK_LEN|V3_SEGMENTS|V3_SEGMENT_LEN|V3_COMMIT_LOOKAHEAD_BLOCKS|COMMIT_CARRIER_V3_LEN)" stellereum/src/cn_vrf.rs
65:pub const EPOCH_LEN: u64 = 7200;
1013:pub const V3_LINK_LEN: usize = 48;
1015:pub const V3_SEGMENTS: usize = 16;
1017:pub const V3_SEGMENT_LEN: u64 = 450;
1019:pub const V3_COMMIT_LOOKAHEAD_BLOCKS: u64 = 360;
1025:pub const COMMIT_CARRIER_V3_LEN: usize = 32 + 8 + V3_SEGMENTS * V3_LINK_LEN + FALCON512_SIG_LEN;
```

```
$ rg -n "DEFAULT_VDF_STEPS_PER_EPOCH|pub fn eval|pub fn verify" stellereum/src/minroot_vdf.rs
38:pub const DEFAULT_VDF_STEPS_PER_EPOCH: u64 = 3_000_000;
312:pub fn eval(seed: &[u8; 48], steps: u64, num_checkpoints: usize) -> MinRootProof {
354:pub fn verify(seed: &[u8; 48], steps: u64, proof: &MinRootProof) -> Option<[u8; 48]> {
```

```
$ rg -n "STELL_CNVRF_V3_DIR|poll_vdf_lane|configure_cnvrf_v3_custody" stellereum/src/node/consensus_driver.rs
197:        // `STELL_CNVRF_V3_DIR`, else `data/cnvrf_v3` beside the node data.
198:        let custody_dir = std::env::var("STELL_CNVRF_V3_DIR")
201:        rt.configure_cnvrf_v3_custody(custody_dir, stellereum::zkml::DEFAULT_CHAIN_ID);
1791:            rt.poll_vdf_lane();
3288:                rt.poll_vdf_lane();
```

```
$ rg -n "apply_cnvrf_v3" stellereum/src/state_engine/apply.rs
2615:            self.apply_cnvrf_v3(block, &status).await
2635:    async fn apply_cnvrf_v3(&self, block: &crate::sharding::Block, status: &[bool]) -> u64 {
```

```
$ rg -n "CNVRF_ABORT_THRESHOLD|CNVRF_ABORT_SLASH_BPS|CNVRF_ABORT_RECOVERY_STREAK|JAIL_RELEASE_DELAY_HEIGHTS|BPS_DENOMINATOR" stellereum/src/staking.rs
301:pub const BPS_DENOMINATOR: u64 = 10_000;
315:pub const JAIL_RELEASE_DELAY_HEIGHTS: u64 = 1_000;
353:pub const CNVRF_ABORT_SLASH_BPS: u64 = 100;
357:pub const CNVRF_ABORT_THRESHOLD: u32 = 3;
363:pub const CNVRF_ABORT_RECOVERY_STREAK: u32 = 20;
```

```
$ rg -n "cnvrf" stellereum/src/metrics.rs
(no output — exit 1)
```

```
$ rg -n "pending_cnvrf_v3_commits_len|has_ready_vdf_beacon|cnvrf_v3_is_epoch_disabled" stellereum/src/ -g '!stellereum/src/runtime/anchors.rs'
(no output — exit 1)
```

```
$ rg -n "CNVRF_V3_ACTIVATION_HEIGHT" stellereum/src/chain_spec.rs
10:    BEACON_DRAW_ACTIVATION_HEIGHT, CNVRF_V3_ACTIVATION_HEIGHT, QC_SPLIT_ACTIVATION_HEIGHT,
135:                "CNVRF_V3_ACTIVATION_HEIGHT",
137:                CNVRF_V3_ACTIVATION_HEIGHT,
243:            ("CNVRF_V3_ACTIVATION_HEIGHT", CNVRF_V3_ACTIVATION_HEIGHT),
```

```
$ rg -n "^fn cnvrf_v3" stellereum/tests/cn_vrf_tests.rs
1320:fn cnvrf_v3_constants_dsts_and_blake3_xof_48() {
1361:fn cnvrf_v3_chain_anchors_commit_verify_and_serde() {
1439:fn cnvrf_v3_slot_by_slot_skip_ahead_and_replay_rejection() {
1509:fn cnvrf_v3_commit_cutoff_lookahead_and_state_machine() {
1568:fn cnvrf_v3_key_rotation_migration_preserves_anchor_validator_id() {
1616:fn cnvrf_v3_reveal_outcomes_rolling_mix_and_fallback_seed() {
1717:fn cnvrf_v3_enc2_secret_custody_and_startup_verify() {
```

**UNVERIFIED** by this document: (a) real VDF throughput on the 1-vCPU hosts; (b) whether the
existing production block time leaves 360 blocks of headroom for the eval; (c) the behaviour of a
mixed-version network (not simulated here); (d) that `stellereum-sdk` / `stell-wallet` still build
against the current working tree. All four must be measured or simulated before activation.
