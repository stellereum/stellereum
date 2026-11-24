# Activation Batch 1 — Coordinated Rollout Runbook

Applies to the live 4-validator cluster (`A`, `B`, `C`, `D`, chain `5757`,
ruleset `7`, `STELL_MIN_BLOCK_MS=400`, `scripts/cluster-nodes.conf`) and any
coordinated `{0,1}` deployment of Activation Batch 1
(`stellereum/docs/specs/ACTIVATION_BATCH_1.md`).

> **Critical rule**: Every validator must run the armed binary **before** the
> chain reaches activation height `H`. Below `H`, the old and new binaries are
> consensus-identical. At and above `H`, they follow different consensus rules.

---

## 0. Topology and Timing Baseline

From `scripts/cluster-nodes.conf` and `scripts/rolling-deploy.sh`:

| Node | Host / SSH | Node dir | Systemd unit (`scope`) | Local RPC | Notes |
|---|---|---|---|---|---|
| `A` | `root@212.113.103.105` | `/root/nodeA` | `stell-nodeA.service` (`system`) | `http://127.0.0.1:8545` | Reference / public RPC (`https://rpc.stellereum.org`), 1 vCPU |
| `B` | local operator host | `/home/imm/stellereum-project/multinode/nodeB` | `stell-nodeB.service` (`user`) | `http://127.0.0.1:8546` | Local multi-core host |
| `C` | `root@213.21.246.5` (`-p 2222`) | `/root/nodeC` | `stell-nodeC.service` (`system`) | `http://127.0.0.1:8545` | 1 vCPU (~68% baseline CPU); most sensitive to stalls |
| `D` | `root@138.124.102.200` | `/root/nodeD` | `stell-nodeD.service` (`system`) | `http://127.0.0.1:8545` | 1 vCPU |

- **Block tempo & jail budget**: At `STELL_MIN_BLOCK_MS=400` and
  `DOWNTIME_MISS_THRESHOLD=42`, the unvoting budget before jailing is
  `42 × 400 ms = 16.8 s` (`rolling-deploy.sh` warns above 90% = `15.1 s`).
  At 400 ms/block, the chain advances ~150 blocks/min (~9 000 blocks/hour).
- **Liveness guard**: `stell-node-guard.timer` restarts a stopped unit within
  60 s. `scripts/rolling-deploy.sh` automatically stops and restarts the guard
  around each unit restart so two processes never open the same sled store.
- **Auto-unjail**: Keep `scripts/auto-unjail.sh` (`stell-auto-unjail`)
  **active** throughout the rollout (never disable it). It only invokes
  `validator unjail` after `release_height` when a jailed node is synced within
  `AUTO_UNJAIL_MAX_GAP=20` of tip, while keeping cold withdrawal keys on their
  own nodes.

---

## 1. Pre-Flight Checks (Before Staging)

### 1.1 Code, manifest, and test gates

Run sequentially on the build host (only when cluster is 4/4, `nice -n 10`,
`CARGO_BUILD_JOBS=2`):

1. **Manifest parity (`stellereum gates --yaml`)**:
   - Confirm `docs/feature_gates.yaml` matches `stellereum gates --yaml` output
     from the release candidate binary (`diff -u docs/feature_gates.yaml <($BIN gates --yaml)` is empty).
   - Confirm `feature_gates::tests::committed_manifest_matches_the_table` passes.
   - Confirm every Batch 1 gate targeted for activation on this chain shows
     `status: SCHEDULED`, the **exact same** `activation_height: H`, and a
     non-`MISSING` proving `test:` entry:
     - Public `{0}` chain: `WASM_TABLE_ELEMENTS_CAP_HEIGHT`,
       `FALCON_HOST_FUEL_V2_ACTIVATION_HEIGHT`,
       `CONTRACT_BLOCK_HASH_ACTIVATION_HEIGHT`,
       `BRIDGE_TARGET_ADDRESS_CAP_HEIGHT` (plus `JAIL_BUDGET_V2_ACTIVATION_HEIGHT`
       only if A6 Option 2/3 was chosen). `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT`
       **must** remain `INERT` (`18446744073709551615` / `u64::MAX`) on `{0}`.
     - Coordinated `{0,1}` chain: additionally verify
       `XSHARD_BOUNCE_ESCROW_REQUIRED_HEIGHT` is `SCHEDULED` at `H` and
       `XPC_ACTIVATION_HEIGHT` is `ACTIVE` (`0`).
2. **`current_activation_schedule()` parity**:
   - Confirm `chain_spec::tests::current_activation_schedule_matches_module_constants`
     passes and every Batch 1 gate is listed in `current_activation_schedule()`
     with the expected `ActivationStatus::ActiveAt(H)` (or `GatedOff` for
     inert gates).
3. **Activation & Wave 3 E2E suites green**:
   - All `activation_gate_*` tests (`activation_gate_contract_block_hash_tests`,
     `activation_gate_bridge_target_address_cap_tests`,
     `activation_gate_xshard_bounce_escrow_tests`, plus any Batch 1 gate tests)
     green.
   - All `w3_*` E2E tests, `w4_engine_hardening_tests`,
     `h9_bridge_target_address_cap`, and `x8_bounce_escrow_gate` green.
   - Full workspace/clippy gate (`./scripts/verify_testnet_ideal.sh`) green.

### 1.2 Activation height headroom & cluster health

1. **Verify `H` headroom**:
   - Read current tip (`stell_blockNumber` on `https://rpc.stellereum.org`).
   - Confirm `H - tip` provides comfortable margin (recommended: at least
     `>= 4 hours` / `>= 36_000` blocks at 400 ms tempo) to complete staging,
     canary soak, 4-node sequential activation, and pre-`H` verification.
2. **Verify 4/4 baseline**:
   ```sh
   ./stellereum status --rpc http://127.0.0.1:8546 --expect 4
   ```
   Require `4/4` active validators, `fragile: false`, and `0` jailed members.
3. **Verify `stell-auto-unjail` is active**:
   ```sh
   systemctl --user is-active stell-auto-unjail
   ```
4. **Verify disk & inode headroom on all 4 nodes** (`df -h` and `df -i` `< 80%`;
   see `ops/safety_recovery_runbook.md` if any node is near 80%).
5. **Take a pre-`H` recovery snapshot** (mandatory safety net):
   - Retain a verified pre-`H` data snapshot (via `scripts/backup_verify.sh`
     on a stopped/quiesced backup or verified snapshot archive) before any
     node crosses `H`. Post-`H` rollback is impossible without a pre-`H`
     snapshot.

---

## 2. Binary Staging (`rolling-deploy.sh stage`)

Staging streams the candidate binary to `<dir>/stellereum.new.next` under
`nice -n 19 ionice -c3`, verifies its SHA-256 against the local binary, and
writes `<dir>/stellereum.new.sha256`. The running `<dir>/stellereum` binary is
**not** touched and validators continue voting normally.

```sh
NEW_BIN=/home/imm/stellereum-project/target/release/stellereum
sha256sum "$NEW_BIN"

# 1. Dry-run to inspect nodes, units, and digest.
./scripts/rolling-deploy.sh stage "$NEW_BIN" --nodes "C A D B" --dry-run

# 2. Stage across all 4 validators (zero downtime).
./scripts/rolling-deploy.sh stage "$NEW_BIN" --nodes "C A D B"
```

Verify that all four nodes report `staged and verified; running binary untouched`
and that the remote `stellereum.new.sha256` matches the local release SHA-256.

---

## 3. Canary & Rolling Activation

> **Strict invariant**: The cluster **must be 4/4 with `fragile: false`**
> before restarting **each** node. Keep `stell-auto-unjail` active throughout.
> If any node is jailed during a restart, **halt the rollout** and wait for
> `stell-auto-unjail` (or manual cold-key unjail after `release_height`) to
> restore `4/4` before touching the next node.

### Recommended activation orders

- **`C -> A -> D -> B`** (recommended for remote-risk-first canary):
  tests the 1-vCPU remote node `C` first while `A`, `D`, `B` hold quorum, then
  remote `A` and `D`, finishing on local `B`.
- **`B -> D -> A -> C`** (alternative for fast-local canary):
  tests local `B` first for instant local inspection/rollback, then `D`, `A`,
  and `C` last.

In either order, only **one** node restarts at a time, and `C` and `B` are
never offline together.

### Step 3.1 — Canary activation (`--canary`)

Run canary on the first node in the chosen order (example uses `C -> A -> D -> B`):

```sh
./scripts/rolling-deploy.sh activate --canary --canary-soak-secs 60 --nodes "C"
```

`rolling-deploy.sh` will:
1. Verify staged SHA-256 on `C`, back up `stellereum -> stellereum.prev`, pause
   `stell-node-guard.timer`, swap `stellereum.new.next -> stellereum`, restart
   `stell-nodeC.service`, and resume `stell-node-guard.timer`.
2. Wait for catch-up within 5 blocks of tip and check `stell_getValidatorStatus`
   and `stell_getValidators`.
3. Soak for 60 s verifying height monotonically advances, `C` is not jailed,
   and cluster remains healthy; auto-rolls back to `stellereum.prev` on failure.

Before proceeding, confirm `4/4`:

```sh
./stellereum status --rpc http://127.0.0.1:8546 --expect 4
```

### Step 3.2 — Activate remaining nodes one by one (`A`, then `D`, then `B`)

Before **each** node, check:
1. `./stellereum status --rpc http://127.0.0.1:8546 --expect 4` shows **4/4**
   active, `fragile: false`, `0` jailed.
2. Current tip height is still strictly `< H` with enough margin to finish
   the remaining nodes safely (if `H - tip` is too small to complete all
   remaining nodes before `H`, **do not cross `H` with a mixed fleet** — roll
   back already-upgraded nodes to `stellereum.prev` immediately before `H`).

Activate each remaining node individually so `4/4` is explicitly verified
between every restart:

```sh
# Node A (verify 4/4 before and after)
./scripts/rolling-deploy.sh activate --nodes "A"
./stellereum status --rpc http://127.0.0.1:8546 --expect 4

# Node D (verify 4/4 before and after)
./scripts/rolling-deploy.sh activate --nodes "D"
./stellereum status --rpc http://127.0.0.1:8546 --expect 4

# Node B (verify 4/4 before and after)
./scripts/rolling-deploy.sh activate --nodes "B"
./stellereum status --rpc http://127.0.0.1:8546 --expect 4
```

*(If using the `B -> D -> A -> C` order, run `--canary` on `B`, then activate
`D`, `A`, `C` one by one with the same 4/4 check between each.)*

---

## 4. Operator Verification Before Crossing `H`

After all 4 nodes are on the new binary and **while `tip < H`**, verify on
every node (`A`, `B`, `C`, `D`) that the gate manifest, activation schedule,
and running binaries are identical:

1. **Running binary SHA-256 parity across all 4 nodes**:
   ```sh
   sha256sum /home/imm/stellereum-project/multinode/nodeB/stellereum
   ssh root@212.113.103.105 'sha256sum /root/nodeA/stellereum'
   ssh -p 2222 root@213.21.246.5 'sha256sum /root/nodeC/stellereum'
   ssh root@138.124.102.200 'sha256sum /root/nodeD/stellereum'
   ```
   All four hashes must be identical.

2. **`stellereum gates` and `stellereum gates --yaml` parity across all 4 nodes**:
   Run `stellereum gates` and `stellereum gates --yaml` on each node's active
   binary and diff against `docs/feature_gates.yaml`:
   ```sh
   /home/imm/stellereum-project/multinode/nodeB/stellereum gates --yaml > /tmp/opencode/gates.B.yaml
   ssh root@212.113.103.105 '/root/nodeA/stellereum gates --yaml' > /tmp/opencode/gates.A.yaml
   ssh -p 2222 root@213.21.246.5 '/root/nodeC/stellereum gates --yaml' > /tmp/opencode/gates.C.yaml
   ssh root@138.124.102.200 '/root/nodeD/stellereum gates --yaml' > /tmp/opencode/gates.D.yaml
   for n in A B C D; do diff -u docs/feature_gates.yaml /tmp/opencode/gates.$n.yaml; done
   ```
   Every node must show zero diff, identical `activation_height: H` for all
   Batch 1 gates, and `SCHEDULED` status (not `INERT`) for every armed gate.

3. **Logs match `current_activation_schedule()` and zero quarantine**:
   Inspect startup logs on each node (`journalctl -u stell-node<X> -n 100` /
   `journalctl --user -u stell-nodeB -n 100`) to confirm:
   - Matching chain ID (`5757`), `FORK_ID`, and `current_activation_schedule()`
     summary/activation heights logged at startup (if emitted) or verified via
     the binary's `stellereum gates` table above.
   - Zero `QUARANTINED (fail-closed Observer)` errors.
   - Cluster `4/4`, `fragile: false`, `stell-auto-unjail` active, and
     `tip < H`.

> **Last safe pre-`H` rollback point**: If any check in §4 fails while `tip < H`,
> stop and restore `stellereum.prev -> stellereum` one node at a time (pausing
> `stell-node-guard.timer`) **before** height `H` is reached.

---

## 5. Post-`H` Verification Checks and Rollback Impossibility

### 5.1 Post-`H` verification (at `tip >= H` through `H + 200`)

1. **Height crosses `H` without stall**:
   Verify `stell_blockNumber` advances smoothly past `H` on `https://rpc.stellereum.org`
   and on all 4 local RPCs, with fresh `FINALIZED block #` log entries on all
   4 validators.
2. **4/4 validator participation**:
   ```sh
   ./stellereum status --rpc http://127.0.0.1:8546 --expect 4
   ```
   Confirm `4/4` active, `fragile: false`, `0` jailed, and `validator_efficiency`
   nominal.
3. **Cross-node `state_root` / `block_hash` equality**:
   Query block `H`, `H + 1`, and `H + 50` across all 4 nodes (`A`, `B`, `C`, `D`)
   and confirm every node reports the identical `block_hash` and `state_root`.
4. **Integrity metrics flat**:
   Inspect `/metrics` on all 4 nodes and confirm zero increments in:
   - `stell_fork_total`
   - `stell_divergence_total`
   - `stell_weak_qc_refused_total`
   - `stell_nil_breaker_fires_total`
5. **Per-gate sanity**:
   Confirm `stellereum gates` reflects the expected `H` and post-`H` RPC /
   execution checks (e.g., RPC and consensus WASM table cap active, Falcon v2
   fuel active, `host.block_hash` returning `block.prev_hash`, bridge 128-byte
   `Withdraw` cap active, and `{0,1}` bounce escrow active if on multi-shard).

### 5.2 Why post-`H` rollback is impossible without snapshot restore

Once the chain finalizes block `H` under the Batch 1 ruleset:

1. **Consensus-rule divergence**: Every block `>= H` is validated and executed
   under the new rules (WASM table cap, `150_000` Falcon fuel + single `(start)`
   gas charge, nonzero `host.block_hash`, 128-byte bridge target cap, and
   `{0,1}` bounce-escrow / A6 jailing rules).
2. **Irreversible BFT finality**: Stellereum has single-block BFT finality;
   committed blocks at `>= H` and their `state_root` / `body_commitment`
   digests cannot be un-finalized in place.
3. **Old binary incompatibility**: Downgrading a node binary to
   `stellereum.prev` after `H` causes that node to compute different gas/state
   results or reject valid `>= H` blocks, leaving it forked or halted.

**Remedy if a catastrophic defect occurs after `H`**: Do **not** swap back to
`stellereum.prev` against post-`H` store data. The only recovery paths are:
1. **Forward hotfix release** compatible with the finalized `>= H` state, or
2. **Coordinated snapshot restore** across **all** validators from the verified
   pre-`H` snapshot (`height < H`) taken in §1.2, clearing/re-initializing safety
   records per `ops/safety_recovery_runbook.md` and booting a matching pre-`H`
   (or fixed) binary before `H` is re-crossed.
