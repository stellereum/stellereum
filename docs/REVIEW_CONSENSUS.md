# Consensus review — safety & liveness (independent, adversarial read)

**Verdict: SOUND WITH FINDINGS — 4 HIGH, 5 MEDIUM, 4 LOW, 0 CRITICAL.**

No path was found on which two nodes can finalize different blocks at one height under the
stated assumptions (`B_w < W/3`, N = 4 live, both activation gates at `u64::MAX`). The live
4-validator configuration is safety-sound as far as static reading and the consensus lib tests
show (`cargo test --lib consensus::` → 84 passed, 0 failed, run during this review).

The HIGH findings are all **rollout / scale blockers rather than live-mainnet forks**:
CN-VRF v3 cannot be switched on (the decision-certificate producer and most verifiers are not
beacon-aware, and the first epoch boundary cannot verify), and finality is unreachable above
roughly 192 equal-stake validators because the µQC committee cap (128) is smaller than the
network-anchored 2/3 the verifier demands while the 250-validator set cap is the documented target.
Each finding below states whether it blocks mainnet **today**.

---

## Findings

| # | Severity | Blocks mainnet? | Area | Finding |
|---|---|---|---|---|
| F1 | HIGH | No at N=4; **yes at the declared 150–250 target** | `consensus/sortition.rs`, `qc_split.rs`, `staking.rs` | Pre-C1-split finality is a µQC whose network-anchored 2/3 is unreachable by a 128-seat committee once the set exceeds ~192 validators; the full-set (CEC) producer is gated off. |
| F2 | HIGH | No today; **yes when CN-VRF v3 is flipped** | `consensus/qc_split.rs`, `runtime/consensus_step.rs`, `runtime/apply.rs`, `sync.rs`, `state_engine/apply.rs`, `light_client.rs` | Only QC verification inside `types.rs`/`anchors.rs` is beacon-aware. With the C1 split still off (today's producer path), the decision certificate is parent-hash-drawn and the finalize gate refuses it; the `last_qc` gate, sync header/body walks, proposer-schedule check, downtime attribution and light client also use the parent-hash draw. The schedule check stays wrong even with the split on. |
| F3 | HIGH | No today; **yes when CN-VRF v3 is flipped** | `runtime/anchors.rs`, `state_engine/apply.rs` | The first epoch boundary under the gate can never verify: `validate_cnvrf_v3_payload` derives the expected seed through the non-zero **bootstrap** beacon, while the producer and `apply_cnvrf_v3` derive it from **zeros**. The beacon chain therefore never starts. |
| F4 | HIGH | No today; **yes when CN-VRF v3 is flipped** | `runtime/anchors.rs`, `docs/CNVRF_V3_ROLLOUT.md:77` | Activating at an exact multiple of 7,200 (what the rollout checklist recommends) makes the activation block an epoch boundary that *must* carry an `epoch_vdf` for an epoch whose `H_freeze` preceded activation — it was never dispatched, so the activation block is unproposable. |
| F5 | MEDIUM | No | `consensus/engine.rs:1558` | `scan_floor` takes the **maximum** peer round; one signed vote claiming a high round narrows the scan back to `scan_lookback` and hides the network's real round — the opposite of the documented "network anchor". |
| F6 | MEDIUM | No at N=4; yes for N ≥ 7 | `consensus/engine.rs:2343` | Deadlock-breaker / peer-chase corroboration is a flat **2** distinct validators. For N ≥ 7 the fault bound is f = 2, so two colluding validators can corroborate an arbitrary round and drive a 65,536-round jump (and suppress the local re-phase). |
| F7 | MEDIUM | No | `consensus/engine.rs:1940–2505`, `runtime/consensus_step.rs:2194` | The per-height budget bounds **peer-driven** drift only; a node more than `MAX_SCAN_SPAN` (4,096) rounds ahead of the network from its own timers cannot see the network's round, cannot adopt (cert "behind" cap), and the re-phase is one-shot per height. Only catch-up/`validate_sync_chain` rescues it. |
| F8 | MEDIUM | No | `runtime/mev_sync.rs:896–941` | "Lock rescue" re-proposes a locked body **verbatim even when another validator authored it**, but `on_proposal` only accepts the round's scheduled proposer (plus an 8-round phase-align). The proposer burns its slot, records the foreign body as live, and can prevote it. Two adjacent comment blocks contradict each other. |
| F9 | MEDIUM (latent) | No (path unwired) | `consensus/rotation.rs:64`, `node/consensus_driver.rs:135`, `staking.rs:3140` | Consensus verification reads a process-global PQ registry populated only at startup/env. The ledger rotation functions write a *different* `PqRegistry`; nothing feeds the verify registry. If rotation is enabled as documented, new-key votes are rejected by every peer and the "trigger 2" cache-invalidation claim is false. |
| F10 | LOW | No | `consensus/sortition.rs:369,386`; `consensus/engine.rs:923,930` | Unguarded `u64` `.sum()` / `acc +=` in the committee draw and µQC compilation, while the rest of the module is `u128`/saturating. Debug panic, release wrap at absurd configured powers. |
| F11 | LOW | No | `sync.rs:271–307` | `verify_finality_for_header` (snapshot-anchor path) does not call `binds_to_parent`, unlike the body walk (`sync.rs:954`) and adopt. Not exploitable thanks to the network-anchored µQC quorum, but the "one verdict" principle is broken. |
| F12 | LOW | No | `consensus/types.rs:266–284` | `validator_signatures` are outside `compute_hash`; one appended bogus entry under the proposer's ids makes `verify_proposer_signature` return false for that delivery of a genuine block. DoS-at-most; re-fetch recovers. |
| F13 | LOW | No | `node/consensus_driver.rs:488–534`, `runtime/apply.rs:1131–1152`, `runtime/consensus_step.rs:207–222` | `last_decision` is not restored on boot nor by the body-walk heal path. A restarted proposer emits `last_qc = None`; every peer that finalized the parent rejects the omission → one wasted proposer slot per restart. |

---

## Details

### F1 — µQC committee cap vs network-anchored quorum: no finality above ~192 validators

`µQC` finality is the only pre-split decision path (`produce_decision_certificate` falls back to
`VoteSet::certificate_with_parent` below the split):

```rust
// stellereum/src/consensus/qc_split.rs:110-114
if qc_split_active_at(height) {
    produce_full_network_certificate_with_pq_keys(votes, target, validators, pq_keys)
} else {
    votes.certificate_with_parent(target, validators, parent_hash)
}
```

The committee is capped at 128:

```rust
// stellereum/src/consensus/sortition.rs:89
pub const MICRO_COMMITTEE_MAX_SIZE: u32 = 128;
// stellereum/src/consensus/sortition.rs:113-115
pub fn micro_committee_size(validator_count: usize) -> u32 {
    validator_count.min(MICRO_COMMITTEE_MAX_SIZE as usize) as u32
}
```

and the verifier anchors the threshold to the **whole network**, not the committee:

```rust
// stellereum/src/consensus/sortition.rs:159-165
let committee_two_thirds = consensus_quorum_min(committee_total_power);
let network_two_thirds = match network_total_power {
    0 => u64::MAX,
    w => consensus_quorum_min(w),
};
committee_two_thirds.max(network_two_thirds)
```

A 128-seat committee can carry `2/3` of the network only if the selected 128 hold ≥ 2/3 of the
stake. With near-uniform stake that requires `N ≤ 192`. But the elected set is allowed to grow to
250 and the code claims this is fine:

```rust
// stellereum/src/staking.rs:205-209
/// A 150-250 window gives TON-class decentralization while keeping BFT
/// gossip O(N^2) tractable; per-block votes use a µQC-16 sortition
/// committee so 250 does not hurt 250ms-1s block times.
pub const MAX_ACTIVE_VALIDATORS: usize = 250;
```

At N = 250 uniform, a 128 committee holds 51.2 % < 2/3, so `has_power_quorum` /
`micro_cert_meets_quorum` is false for every certificate, and the CEC producer is gated off
(`QC_SPLIT_ACTIVATION_HEIGHT = u64::MAX`). The chain simply stops finalizing. The comment is also
stale ("µQC-16"). `to_validator_set` truncates deterministically, so this is not a fork — it is a
silent finality cliff at exactly the scale the design says it targets.

*Blocks mainnet? No for the live 4-validator set; yes for the documented decentralization target.*

---

### F2 — CN-VRF v3 is wired only into the local verifier, not the rest of consensus

The beacon-aware entry points exist and are used in `runtime/anchors.rs` and
`QuorumCertificate::verify_with_beacon`. Every other verification site still calls the
parent-hash form — **including the decision-certificate producer**, so the node cannot even
finalize the first block after activation.

**Producer (the decisive failure — the QC a node builds for itself is refused by its own
beacon-aware power gate):**

```rust
// stellereum/src/consensus/qc_split.rs:110-114
if qc_split_active_at(height) {
    produce_full_network_certificate_with_pq_keys(votes, target, validators, pq_keys)
} else {
    votes.certificate_with_parent(target, validators, parent_hash)
}
```

With the split still at `u64::MAX` and CN-VRF v3 active, the legacy branch compiles the µQC from
`derive_sortition_committee(... parent_hash)` (`consensus/engine.rs:858-869`). The finalize gate
then attributes that same QC through the **beacon** draw
(`qc_signed_power_for_height` → `signers_set_with_beacon`), finds no committee match, and refuses:

```rust
// stellereum/src/runtime/apply.rs:690-692
let signed = self.qc_signed_power_for_height(&in_force, qc);
let required = in_force.quorum_power();
if signed < required { ... return None; }
```

So at the activation height the network cannot finalize anything: every local decision carries a
parent-hash µQC that every beacon-aware verifier (including its own) rejects. This is independent
of F3/F4 and would halt even if the epoch-boundary logic were correct.

**`last_qc` downtime evidence (proposal path — halts every height with evidence):**

```rust
// stellereum/src/runtime/consensus_step.rs:252-269
let set = self.validator_set_for_height(parent_h);
...
if !qc.verify(&set) {
    let signed = set.qc_signed_power(qc);
    ...
    return Err(format!(
        "proposal: downtime evidence carries only {signed} of {required} required power at height {parent_h}"
    ));
}
```

At/after activation an honest `last_qc` is a µQC drawn from the **beacon** committee; `qc.verify`
re-derives it from `cert.sortition_parent`, so the committees differ and the proposal is refused.
A proposer that knows the parent decision must include the evidence (`check_last_qc_evidence`
rejects the omission), so no honest proposal can carry it.

**Sync (header anchor + body walk + proposer schedule):**

```rust
// stellereum/src/sync.rs:301
if !qc.verify(validators) { ... }
// stellereum/src/sync.rs:960
if !qc.verify(&validators) { ... }
// stellereum/src/sync.rs:262
(0..=bound).any(|r| validators.proposer_for(height, r).as_ref() == Some(proposer))
```

`proposer_matches_schedule` uses the parent-hash draw even though the block was proposed under the
beacon draw; `verify_finality_for_header` and the body walk use the non-beacon verifier. A node
that restarts or falls behind cannot sync past the activation height.

**Downtime attribution (apply) silently stops:**

```rust
// stellereum/src/state_engine/apply.rs:3722-3725
if !cert.verify(val_set) {
    return 0;
}
let signers = cert.signers_set(val_set);
```

Same parent-hash verifier and attribution. Every node derives the same (wrong) verdict, so no
fork — slashing silently stops.

**Light client:**

```rust
// stellereum/src/light_client.rs:526
if !cert.verify(validators) { ... }
```

*Fail-closed, but fail-closed here means "the network stops".* Fix: thread the beacon through a
single `verify_qc_for_height`-style helper and make it the only call site (the runtime already has
one; `sync.rs`, `light_client.rs`, `state_engine/apply.rs` and `check_last_qc_evidence` do not use
it).

---

### F3 — the first boundary beacon can never verify (bootstrap vs zeros)

The runtime's beacon lookup falls back to a **deterministic non-zero bootstrap** for an epoch whose
`H_freeze` predates activation:

```rust
// stellereum/src/runtime/anchors.rs:203-211
if epoch == 0 || !self.cnvrf_v3_is_active_at(h_freeze) {
    let output = crate::cn_vrf::epoch_raw_seed(
        self.cnvrf_v3_chain_id,
        epoch,
        &[0u8; crate::cn_vrf::V3_LINK_LEN],
        &[0u8; 32],
        &[0u8; crate::cn_vrf::V3_LINK_LEN],
    );
    return Some(crate::consensus::EpochBeacon { epoch, output });
}
```

`validate_cnvrf_v3_payload` recomputes the expected seed through that helper:

```rust
// stellereum/src/runtime/anchors.rs:958-969
if let Some((freeze_hash, freeze_mix)) = self.cnvrf_freeze_inputs.get(&epoch).copied() {
    let expected_seed = epoch_raw_seed(
        self.cnvrf_v3_chain_id,
        epoch,
        &self
            .active_epoch_beacon(block.height.saturating_sub(1))
            .map(|b| b.output)
            .unwrap_or([0u8; crate::cn_vrf::V3_LINK_LEN]),
        &freeze_hash,
        &freeze_mix,
    );
    if vdf.raw_seed != expected_seed { return Err(...); }
}
```

The **producer** and the **state engine** both use the committed map only, with a zeros fallback:

```rust
// stellereum/src/runtime/anchors.rs:720-724 (VDF dispatch at H_freeze)
self.finalized_epoch_beacons
    .get(&(target_epoch - 1))
    .copied()
    .unwrap_or([0u8; crate::cn_vrf::V3_LINK_LEN])
```
```rust
// stellereum/src/state_engine/apply.rs:2928-2934
let prev_beacon = if e == 0 { [0u8; 48] } else {
    epoch_beacons.get(&(e - 1)).copied().unwrap_or([0u8; 48])
};
let expected = epoch_raw_seed(self.chain_id, e, &prev_beacon, freeze_hash, freeze_mix);
```

At the first boundary under the gate the previous epoch has **no committed beacon** (no boundary
block ran under the gate), so `epoch_beacons.get(e-1)` is `None` → zeros, while
`active_epoch_beacon(block.height - 1)` returns the bootstrap → non-zero. The two seed derivations
differ, every validator that recorded the freeze input (i.e. every live validator) rejects the
boundary block, and the state engine never records the beacon. Because no epoch beacon is ever
recorded, the same mismatch repeats at every subsequent boundary. This is a deterministic
activation halt, independent of activation height.

---

### F4 — activating at an exact 7,200 multiple is impossible, and the rollout doc recommends it

`docs/CNVRF_V3_ROLLOUT.md:77-83` says:

> **Choose `H` as an exact multiple of 7,200.** … epoch `E`'s `H_freeze = H - 360 < H`, so epoch
> `E` is bootstrapped deterministically on every node and needs no VDF.

That reasoning covers `active_epoch_beacon` (proposer/QC), but ignores the **boundary block
payload**. At `H = E*7200` the activation block *is* the epoch boundary, and validation requires an
`epoch_vdf`:

```rust
// stellereum/src/runtime/anchors.rs:932-938
if block.height.is_multiple_of(EPOCH_LEN) && block.height >= EPOCH_LEN {
    let epoch = block.height / EPOCH_LEN;
    let Some(vdf) = payload.and_then(|p| p.epoch_vdf.as_ref()) else {
        return Err(format!(
            "proposal: boundary block {} omits the epoch {epoch} MinRoot VDF beacon",
            block.height
        ));
    };
```

The VDF for epoch `E` is only dispatched at `H_freeze = E*7200 - 360`, and the dispatcher is gated
on activation:

```rust
// stellereum/src/runtime/anchors.rs:697-704
if self.cnvrf_v3_is_active_at(finalized_height)
    && finalized_height >= crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS
{
    if let Some(boundary) = finalized_height.checked_add(crate::cn_vrf::V3_COMMIT_LOOKAHEAD_BLOCKS) {
        if boundary.is_multiple_of(crate::cn_vrf::EPOCH_LEN) { ... }
```

With `H = E*7200`, `H_freeze = H - 360 < H` is inactive, so no VDF exists; the proposer's
`build_cnvrf_v3_payload` only fills `epoch_vdf` from `ready_vdf_beacons` (`anchors.rs:587-592`),
so the activation block is proposed without the beacon and every validator refuses it. There is no
"activation epoch is exempt" branch. A mid-epoch activation avoids this specific failure but runs
into F3 at the next boundary — i.e. **there is currently no activation height that works.**

---

### F5 — a single peer can narrow the quorum scan and hide the network's round

```rust
// stellereum/src/consensus/engine.rs:1558-1563
fn scan_floor(&self) -> Round {
    let anchor = self.max_peer_round().unwrap_or(self.round).min(self.round);
    let floor = anchor.saturating_sub(self.scan_lookback);
    let hard = self.round.saturating_sub(MAX_SCAN_SPAN);
    floor.max(hard).min(self.round)
}
```

`peer_rounds` is written for **every verified same-height vote**, before any round-window check:

```rust
// stellereum/src/runtime/consensus_step.rs:999-1004
self.hc.note_peer_round(vote.voter, vote.round);
```

A single Byzantine member can sign one vote at `u32::MAX`; `max_peer_round()` then equals our own
round, so `anchor = self.round` and the floor becomes `round - scan_lookback` (8) instead of
`round - 8 - peer_lag`. A node that is ahead of the network (the exact case the "NETWORK ANCHOR"
comment at `engine.rs:1519-1530` exists for) loses sight of the network's round until the 300 s
local re-phase widens `scan_lookback` to 4,096. The comment only argues about low claims and CPU
widening; it never considers that the `max` lets a high claim *remove* the network anchor.

---

### F6 — corroboration "2 distinct peers" is below the fault bound for N ≥ 7

```rust
// stellereum/src/consensus/engine.rs:2343-2348
fn breaker_corroboration(&self) -> usize {
    if self.validators.len() >= 3 {
        2
    } else {
        1
    }
}
```

Under the protocol's own model (`B_w < W/3`) a set of 7 permits **two** Byzantine validators. Two
colluding validators are enough to satisfy `corroborated_peer_round` for an arbitrary round,
which simultaneously (a) suppresses the local re-phase (`deadlock_local_reset_due` requires *no*
corroborated peer ahead) and (b) lets `apply_deadlock_jump` move the node up to
`MAX_DEADLOCK_JUMP = 65_536` rounds forward. That is far outside `REPHASE_SCAN_WINDOW` (4,096) and
`MAX_SCAN_SPAN` (4,096); the honest node then cannot scan or adopt at that height (see F7) and
needs catch-up/snapshot. Same threshold at `note_peer_vote_round:918` and
`observe_peer_round:2221`. Correct threshold is `f + 1 = floor((n-1)/3) + 1`, not a constant 2.
Not reachable at N = 4 (f = 1); it is a real round-DoS at the 150–250 target.

---

### F7 — the per-height budget + one-shot re-phase can strand a node ahead of the network

The new budget is correct for what it claims (peer-driven drift) and the deadlock breaker does
bypass it:

```rust
// stellereum/src/consensus/engine.rs:1943-1955
let remaining = MAX_PEER_ROUND_ADVANCE_PER_HEIGHT.saturating_sub(self.peer_round_advance_used);
if remaining == 0 { return; }
let target = round
    .min(self.round.saturating_add(ROUND_LOOKBACK))
    .min(self.round.saturating_add(remaining));
```
```rust
// stellereum/src/consensus/engine.rs:2360-2369 — apply_deadlock_jump never touches the budget
pub fn apply_deadlock_jump(&mut self, target: Round) -> bool { ... self.round = target; ... }
```

Two gaps remain, and they combine:

1. **Own-timer drift is unbounded.** `next_round` increments the round once per timeout and does
   not consume the budget; the timeout ladder caps at `base + 10 s` ≈ 13 s
   (`consensus/sortition.rs:719-742`). Nothing bounds `self.round - network_round`.
2. **The re-phase is one-shot per height** and only adds one round:

```rust
// stellereum/src/consensus/engine.rs:2475-2495
let needs_work = !self.rephase_applied
    || self.proposal.is_some()
    || self.proposal_round.is_some()
    || self.locked.is_some() && drop_lock;
if !needs_work { return false; }
...
self.round = self.round.saturating_add(1);
...
self.scan_lookback = REPHASE_SCAN_WINDOW;
self.rephase_applied = true;
```

Once a node is more than 4,096 rounds ahead of the network's round (≈ 15 hours of 13 s timeouts,
or much faster with the peer budget helping), `scan_floor` cannot reach the network's round and
the re-phase cannot fire again. Adoption is also refused:

```rust
// stellereum/src/runtime/consensus_step.rs:2194-2205
if certificate.round != self.hc.round {
    let behind = self.hc.round.saturating_sub(certificate.round);
    let lookback = crate::consensus::ROUND_LOOKBACK as u64;
    let forward = certificate.round.saturating_sub(self.hc.round);
    let forward_ok = lock_supersedes && forward as u64 <= lookback;
    if (certificate.round > self.hc.round && !forward_ok)
        || behind as u64 > crate::consensus::MAX_SCAN_SPAN as u64
    { return Err(...); }
}
```

The node is then recovered only by catch-up / `validate_sync_chain` (which does not compare the
local round) or a snapshot — and catch-up is explicitly deferred while "live adopt is fresh"
(`consensus_driver.rs:1205`). So: not a permanent wedge in the absolute (catch-up still works),
but the local recovery mechanisms this design relies on are unavailable. The in-code claim
"maximum peer-induced drift plus the node's own timeout drift still fits comfortably inside
REPHASE_SCAN_WINDOW" (`engine.rs:1190-1194`) is false without a bound on the second term.

*Answer to "can the per-height budget wedge a node?": not by itself, and the deadlock breaker is
still reachable (it is not budget-charged, and it is required when the network is ahead). But the
budget does not bound the drift that actually matters, and the one-shot re-phase cannot re-open
the window.*

---

### F8 — "lock rescue" re-proposes bodies its own peers refuse

```rust
// stellereum/src/runtime/mev_sync.rs:896-911
if let Some((locked_hash, _)) = self.hc.locked {
    // PENTEST P1 (liveness): a lock may name a body ANOTHER validator
    // authored ... Only OUR OWN body may be re-proposed; otherwise fall through
    ...
    // LOCK RESCUE (protocol-critical, NOT a bug): the locked value is
    // re-proposed VERBATIM even when another validator authored it.
    if let Some(body) = self.blocks.get(&locked_hash).cloned() {
```
```rust
// stellereum/src/runtime/mev_sync.rs:936-940
let expected = self.expected_proposer_now();
self.hc.receive_proposal_for(self.id, locked_hash, expected).ok()?;
return Some(body);
```

`receive_proposal_for(self.id, ...)` records **us** as the proposer of a body whose
`block.proposer` is someone else. The receiver's acceptance test is the round's scheduled
proposer:

```rust
// stellereum/src/runtime/consensus_step.rs:1153, 1193
if Some(block.proposer) != self.expected_proposer_now() { ... }
if Some(block.proposer) != self.expected_proposer_now() {
    return Err("proposal: wrong proposer".to_string());
}
```

The only escape is the +8-round phase-align, i.e. the body's original author must own one of the
next eight slots. Otherwise peers drop the body, while our node has `has_live_proposal() == true`
for it and may prevote a value nobody will prevote. Two adjacent comments assert opposite
policies; the code implements the second. Either restrict the rescue to `body.proposer == self.id`
and rely on the lock rule/`demanded` path, or make `on_proposal` use `proposer_matches_schedule`
(which is what sync/adopt already accept). The latter is a protocol change and needs the spec
update.

---

### F9 — PQ key rotation never reaches the registry consensus verification reads

```rust
// stellereum/src/consensus/rotation.rs:64-76
pub fn pq_key_at_height(validator: &ValidatorId, height: Height)
    -> Option<(PqScheme, Vec<u8>)>
{
    let reg = PQ_COMMITTED_REGISTRY.read()...;
    if reg.record_of(validator).is_some() {
        return reg.get_active_key(validator, height);
    }
    drop(reg);
    get_validator_pq_key(validator)
}
```

`PQ_COMMITTED_REGISTRY` is written by `register_validator_pq_key` (legacy `activated_at = 0`) and by
the test-only announce. The production rotation API takes a caller-owned registry and only mirrors
the head key into `validator_pq_keys`:

```rust
// stellereum/src/staking.rs:3178-3190
pub fn pq_apply_rotation(&mut self, registry: &mut PqRegistry, validator: ValidatorId, ...) {
    registry.apply_rotation(validator, now_height, true)?;
    if let Some((scheme, pubkey)) = registry.current_key_of(&validator) {
        self.validator_pq_keys.insert(validator, (scheme, pubkey));
    }
```

Nothing in `stellereum/src` calls `pq_announce_rotation` / `pq_apply_due_rotations`
(`rg` finds zero non-test callers), and startup registration is env/static:

```rust
// stellereum/src/node/consensus_driver.rs:135-139
stellereum::consensus::register_validator_pq_key(
    self_vote_id,
    stellereum::post_quantum::PqScheme::Falcon512,
    our_falcon.public_key.clone(),
);
```

Consequences: the documented "ledger-side rotation ops take effect on the verify path only through
this registry" (`types.rs:1313-1319`) is not true; `verified_vote_cache` trigger 2 can never fire
from a ledger rotation (no `register_validator_pq_key`, no `invalidate_verified_vote_cache`); and
the day rotations are enabled, a rotated validator's votes/proposals are rejected by every peer
until each node restarts with a new env. The path is currently unwired, hence no live impact — but
this is exactly the kind of latent wiring gap that turns into a halt during an upgrade.

---

### F10 — unguarded `u64` sums on the committee path

```rust
// stellereum/src/consensus/sortition.rs:369
let mut total_power: u64 = pool.iter().map(|(_, p)| *p).sum();
// stellereum/src/consensus/sortition.rs:386-387
for (idx, (_id, power)) in pool.iter().enumerate() {
    acc += *power;
```
```rust
// stellereum/src/consensus/engine.rs:923,930-935
let committee_total: u64 = committee.iter().map(|id| validators.power_of(id)).sum();
...
let signed_power: u64 = committee.iter().enumerate()...
    .map(|(_, id)| validators.power_of(id))
    .sum();
```

`staking.rs:2409-2417` itself documents that `bond` accepts any `u64` and that 250 validators at
`u64::MAX` would make a raw `.sum()` panic in debug / wrap in release, and fixed
`ValidatorSet::total_power`; these four sites were not converted. At the live 1 B supply cap the
inputs never approach `u64::MAX`, so this is a tripwire, not a live bug. (`sum::<u64>()` overflow
also differs between debug and release, i.e. a determinism asymmetry across build profiles.)

---

### F11 — snapshot-anchor path omits the µQC parent pin

```rust
// stellereum/src/sync.rs:295-305
if !proposer_matches_schedule(validators, height, proposer, qc.round) { ... }
if !qc.verify(validators) { ... }
Ok(())
```

Compare the body walk, which does pin it, and adopt:

```rust
// stellereum/src/sync.rs:954 and runtime/consensus_step.rs:2256
if !qc.binds_to_parent(&b.prev_hash) { return Err(...); }
```

Not exploitable today: a µQC still needs 2/3 of the whole network's power
(`pq_micro_required_power`), so a relay cannot choose a committee; and post-split only the CEC
(which has no committee) verifies. Still, "verification and binding describe the same committee"
should be enforced on every finality boundary, not three of four.

---

### F12 — proposer-signature list is malleable outside the block hash

```rust
// stellereum/src/consensus/types.rs:266-284
for (signer_id, sig_bytes) in &block.validator_signatures {
    if *signer_id != block.proposer && *signer_id != expected_addr { continue; }
    if sig_bytes.len() != scheme.signature_size() { continue; }
    if verify_pq_signature(scheme, &pk, &hash, sig_bytes) { return true; }
    return false;
}
```

`compute_hash` excludes `validator_signatures` (they sign the hash). A relay can append one
correctly-sized invalid signature under `block.proposer` (or the derived PQ address) to a genuine
block without changing its hash, and the first matching entry now returns `false`. The fail-closed
direction is right; the cost is a refused delivery of a valid block, recoverable by re-fetching
the canonical bytes. Low, but worth knowing when debugging "invalid proposer signature" reports.

---

### F13 — `last_decision` is in-memory only

```rust
// stellereum/src/node/consensus_driver.rs:488-502
Ok(Some((fh, fhash))) => {
    rt.finalized.push((fh, fhash));
    if fh + 1 > rt.hc.height {
        rt.hc = HeightConsensus::new(fh + 1, rt.validators.clone());
        ...
```

No `last_decision` assignment; `apply_and_advance` (used by the heal walk) also does not set it
(`runtime/apply.rs:1131-1152`). Only local finalize (`apply.rs:667`), adopt
(`consensus_step.rs:2409`) and catch-up (`node/sync.rs:927`) populate it. A node that restarts at
height H → proposes at H with `last_qc = None` → peers that finalized H-1 reject the omission
(`consensus_step.rs:211-222`) → the slot is wasted. Self-heals after one finalize, but it is
avoidable by persisting the decided QC (it is already stored with the block) and seeding
`last_decision` at boot.

---

## Direct answers to the review questions

* **Two conflicting finalizations at one height?** No path found under `B_w < W/3`. The needed
  invariants all hold: quorum curves are exact (`u128` where it matters), signers are attributed
  only after their signatures verify, duplicate/repeated markers cannot double-count, a µQC needs
  2/3 of the *network* (not just its committee), the producer refuses an under-quorum aggregate,
  the decide path requires a prevote quorum and a precommit quorum for the same value in the same
  round, locks are monotonic and only released by a *newer* block polka, adopt refuses a
  conflicting cert at or below the lock, and the finalize gate re-checks the deciding QC against
  the set in force at that height. The one asymmetry (a stale `hc.validators` mid-height) can only
  under-count and stall, and the finalize gate catches it.
* **Can one Byzantine validator stall the set?** At N = 4, not by itself: the other three still
  form 2/3. It can degrade liveness (F5 narrows the scan until the 300 s re-phase; F8 wastes a
  proposer slot it owns; a signed far-future vote is recorded by design), and F7's own-timer drift
  can take a node out of the scan/adopt range, but that is self-inflicted/exogenous, not a
  one-key finality stop. At N ≥ 7 the flat-2 corroboration (F6) makes a **two-key** round-DoS real.
* **Determinism.** Every finality/round decision is a pure function of block bytes + committed
  state + the validator set resolved per height. The exceptions are local and do not feed a
  verdict: timers (view changes/deadlock), `last_decision` (F13), the freeze-input cache (F3,
  gated), and the process-global PQ registry (F9, startup config). No `HashMap` order reaches a
  decision.
* **Frozen core (`AGENTS.md` §7).** No wire/format, quorum-value, `apply()`, staking-math or
  signature-domain violation found. F1 (committee cap / quorum) and F8 (acceptance rule) would
  require a spec update if fixed as proposed; the rest are local policy or gated-path wiring.

---

## What I would fix before mainnet (ordered by risk)

1. **Do not flip `CNVRF_V3_ACTIVATION_HEIGHT` until F3+F4 are fixed and a full activation test
   (activation block + first two epoch boundaries, 3+ nodes, restart one mid-epoch) is green.**
   Today neither an exact-multiple activation nor a mid-epoch activation can cross the first
   boundary. Fix by using one seed-source function for producer, validator and apply (including
   the bootstrap-beacon case), and by making the boundary `epoch_vdf` requirement aware of the
   first active epoch.
2. **Fix F2 before that flip**: make `produce_decision_certificate` (the µQC producer) use the
   beacon draw, and route `check_last_qc_evidence`, `sync.rs` (header + body +
   `proposer_matches_schedule`), `state_engine::apply_downtime_slash_with_set` and `light_client`
   through the same beacon-aware `verify_qc_for_height` / `expected_proposer_at` helpers the
   runtime already has. Then add a test that locally finalizes one block above the activation
   height.
3. **Resolve F1 before advertising >192 validators.** Either raise `MICRO_COMMITTEE_MAX_SIZE` to at
   least `floor(2·250/3)+1 = 167` (which then needs a *unanimous* committee — 168+ gives margin),
   or make the full-set CEC the pre-split producer, or refuse to elect more validators than the
   µQC can certify (fail loudly, not by stalling). Add a test that builds a 250-validator set and
   shows either finality or an explicit governed refusal.
4. **F5/F6 (single- and two-peer round attacks):** anchor the scan floor on the *minimum*
   corroborated honest round (or clamp a single peer's claim), and make the corroboration
   threshold `f+1` instead of 2. Both are cheap and remove a one-key liveness attack.
5. **F7:** allow the local re-phase to re-arm (bounded, e.g. once per `REPHASE_SCAN_WINDOW`
   no-progress windows) and/or cap `self.round - corroborated_peer_round` so adoption's
   `MAX_SCAN_SPAN` window always contains the network. Add a harness case: node ahead by 5,000
   rounds, network finalizing, assert recovery without catch-up.
6. **F8:** stop re-proposing foreign-authored locked bodies (the peers reject them) or accept
   `proposer_matches_schedule` on the proposal path — the latter needs a spec update because it
   changes block acceptance.
7. **F9:** either wire `pq_apply_rotation` into `consensus::rotation` (register + invalidate) and
   add a replay test, or make the ledger refuse rotation while consensus cannot read it.
8. **F10–F13 (LOW):** convert the four raw sums to `u128`/saturating; add `binds_to_parent` to
   `verify_finality_for_header`; persist and seed `last_decision` at boot; decide whether the
   proposer-signature list should be hash-committed (would be a frozen-core change).

---

## Reviewed but found nothing (auditable coverage)

* **Quorum arithmetic.** `consensus_quorum_min` uses `u128` (`sortition.rs:24-29`),
  `ValidatorSet::quorum_power` uses `total_power_exact()` and refuses a > `u64::MAX` total
  (`types.rs:705-768`), `qc_meets_quorum` fails closed on unrepresentable totals (`:811-813`),
  `micro_cert_meets_quorum` recomputes the network term in `u128` (`:2095-2125`),
  `epoch_cert_meets_quorum` is `u128` (`:2229-2237`). `VoteSet` power uses `saturating_add`
  (`engine.rs:588-589`), and every quorum read is gated on `power_total_representable`
  (`:690-710`).
* **Duplicate / mixed signers.** `VoteSet` stores one vote per voter; the fused and separate QC
  paths union signers through a `HashSet` (`types.rs:1645-1693`, `:2412-2458`); repeated identical
  µQC markers resolve and are counted once (`resolve_micro_certificate:2267-2290`); different
  parents fail closed. A cert carrying a valid CEC plus a sub-quorum µQC cannot inflate finality
  (the verdict is per-marker OR) and the extra attributed members must have signed the same
  preimage, so the union is genuine.
* **Bitmask parsing.** Canonical decode bounds `sig_count` by `MAX_COMMIT_CERT_SIGNERS`
  (`types.rs:600`), the verifier requires the exact bitmask length, rejects trailing set bits and
  out-of-range signer bits (`:1930-1980`, `:2154-2162`), and requires compact/full signature shape
  (`:1982-1987`, `:2167-2172`). `decode_pq_micro_envelope`'s bincode fallback is bounded by the
  payload size in practice; no panic path found.
* **`MAX_COMMIT_CERT_SIGNERS`.** Enforced at the head of `verify_unified` (`:1737`),
  `verify_and_signed_power_inner` (`:1635`), `signers_set` (`:2402`) and the producers
  (`qc_split.rs:209-215`); the `bincode` fallback cannot bypass the later structural checks.
* **`binds_to_parent`.** Enforced on adopt (`consensus_step.rs:2256`), replay
  (`apply.rs:993`), and the sync body walk (`sync.rs:954`); only the snapshot header path omits it
  (F11, defense in depth only).
* **Fused `verify_and_signed_power`.** Same anti-DoS cap, same ambiguity refusal, same per-marker
  membership/committee/signature checks and the same `micro_cert_meets_quorum` /
  `epoch_cert_meets_quorum` as `verify` (both call the same helpers). The equivalence test
  `verify_and_signed_power_matches_separate_calls` passes. The adopt gate checks both
  `quorum_ok` **and** `signed >= quorum_power` (`consensus_step.rs:2264-2295`), so a
  union-of-two-sub-quorum-markers can never pass.
* **Lock rules.** `decide_prevote` nil-votes against a conflicting proposal (`engine.rs:1395-1408`);
  the unlock is newest-polka-wins and nil-polka never unlocks (`:1652-1719`); precommit honours the
  lock and locks at the polka round (`consensus_step.rs:1352-1365`); `try_precommit_quorum`
  requires the prevote quorum in the same round and a consistent value (`engine.rs:1868-1882`);
  `make_precommit` follows `best_polka`, which is monotonic because `note_polka` refuses older
  rounds (`:1781-1803`), so a lower-round polka cannot regress the lock. Adopt refuses a
  conflicting cert at `round <= locked_round` and accepts a later-round cert as the Tendermint
  unlock proof (`consensus_step.rs:2312-2316`).
* **Nil handling.** A nil quorum is not a polka and cannot shadow one (`engine.rs:1723-1763`);
  precommits are never decided on a nil quorum (`:1860`); the nil breaker is one-shot per streak
  and only widens (`:2145-2158`).
* **Proposal freshness / timestamp.** Envelope round is checked after authentication
  (`consensus_step.rs:1143`), one value per round is enforced (`engine.rs:1369-1381`), and the
  timestamp bounds are pure functions of parent/child with no wall clock
  (`consensus_step.rs:39-85`).
* **Per-height validator set.** `validator_set_for_height` stages changes at `activation <= h`,
  walks a bounded history for older heights, and falls back to the oldest known set in the
  conservative direction (`consensus_step.rs:1816-1839`); the finalize gate recomputes the QC power
  against that set (`apply.rs:677-707`), so a stale `hc.validators` can only stall, not fork.
* **Determinism.** No `HashMap` iteration order reaches a decision: `VoteSet::scope` reads
  identical fields, `quorum_target` can return at most one over-quorum target (`2q > W`), the
  proposer table sorts ids explicitly (`types.rs:911-919`), the CEC producer sorts ids
  (`qc_split.rs:220-221`), and `CnVrfV3BlockPayload::canonical_bytes` sorts commits
  (`sharding/block.rs:218-235`). `deterministic_round_timeout_ms` has no `Instant`/`SystemTime`
  (the only clock reads are the timers that trigger view changes and the deadlock breaker, both
  local liveness policy, never a finality verdict).
* **Frozen core (AGENTS.md §7).** No wire-format, quorum-value, `apply()`, staking-math or
  signature-domain change was found in scope. The new `MAX_PEER_ROUND_ADVANCE_PER_HEIGHT` is local
  policy (not serialized); `HeightConsensus` never goes on the wire. The only spec-relevant
  proposals are F8's acceptance-rule change and F1's committee/quorum sizing, which would need a
  spec update if chosen.
* **Targeted test run.** `cargo test --lib consensus:: --no-fail-fast` → `84 passed; 0 failed;
  0 ignored; 1254 filtered out`. No whole-suite run was performed (out of scope for this review).

---

### Notes / limits of this review

* I could not diff against a baseline: the workspace is not a git repository, so "recent changes"
  were assessed from the in-tree comments/naming (`PENTEST F-9`, "fused", "single-pass", the
  `CNVRF_V3_*` gates) rather than a commit delta.
* F9's "no production caller" claim is a grep over `stellereum/src` (zero non-test hits for
  `pq_announce_rotation` / `pq_apply_due_rotations`); out-of-tree callers are UNVERIFIED.
* F1's break-even (≈192) assumes near-uniform stake; with a concentrated stake distribution the
  top 128 can hold ≥ 2/3 and the µQC remains reachable. The uniform case is the one the
  staking/decentralization target implies.
* No live-cluster measurement was taken; all numeric claims are from code constants.
