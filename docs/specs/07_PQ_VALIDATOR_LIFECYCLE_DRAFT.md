# 07 — PQ Validator Lifecycle, Key Separation & Remote Signer (W3 Spec)

**Status: W3 IMPLEMENTATION SPECIFICATION (pending W0/W2 gate and Ruleset v7 activation).**
This document replaces the audit-only draft with an actionable step-by-step specification (`file:line` anchored to canonical `stellereum/src/`) so W3 code echelons can execute immediately after W0/W2 close. Changes to wire enums, `StakingLedger`, `commitment.rs`, signature domains, and `FORK_ID` remain subject to `AGENTS.md §7` (spec + audit note + full frozen-core gate).

---

## 0. Current W3 Blockers in Code (Verified Baseline)

1. **No withdrawal credential in `ValidatorStake` (`stellereum/src/staking.rs:878-900`):**
   * `SysCallUnbond` (`svm.rs:2285`), `SysCallUnjail` (`svm.rs:2306`, `state_engine/apply.rs:3917`), `SysCallRotateValidatorKey` (`svm.rs:2348`), `SysCallClaimRewards` (`svm.rs:2459`), and `SysCallWithdrawSelfBond` (`svm.rs:2517`) all require `ctx.sender == *validator`.
   * Under FULL-PQ (`sharding/transaction.rs:1255-1314`), `tx.from` (`ctx.sender`) MUST be a `PQ1` Falcon-512 address (`post_quantum.rs:262-269`), whereas `ValidatorId` for existing nodes is an Ed25519 `validator.key` pubkey (`node/bootstrap.rs:774-775`, `runtime/anchors.rs:23`, `node/consensus_driver.rs:251`). Existing validators therefore cannot sign any self-custody staking transaction at all, and binding `validator_id == voting_key_address` would couple hot consensus signing with cold stake withdrawal.
2. **Disconnected PQ registries (`pq_registry.rs`, `consensus/rotation.rs`, `staking.rs`, `rpc/state.rs`):**
   * `node/consensus_driver.rs:286-328` loads `./keys/falcon.key` and `STELL_PEER_PQ_KEYS` into process-local `consensus::register_validator_pq_key` (`consensus/rotation.rs:13-41`), writing `PQ_VALIDATOR_KEYS` (`:8-10`) and `PQ_COMMITTED_REGISTRY` (`:52-54`).
   * `staking.rs:3338-3477` defines membership-gated `PqRegistry` hooks (`pq_register_key`, `pq_announce_rotation`, `pq_apply_rotation`, `pq_apply_due_rotations`, `pq_active_key`), with zero production callers in `stellereum/src`.
   * `rpc/state.rs:335-339` maintains a third isolated `pq_registry_handle()` `OnceLock` read by `stell_getPqKey` / `stell_getPqRegistryStatus` (`rpc/reads.rs:2394-2469`).
   * `InMemoryStateEngine` (`state_engine/mod.rs:165-360`), `commitment.rs:971-1271`, and `DomainSnapshot` (`storage.rs:2677-2694`) do not persist or commit `PqRegistry`.
   * `pq_registry.rs:612-623` (`verify_rotation_announcement`) unconditionally returns `false`; `announce_rotation` (`:407-416`) uses `saturating_add`, lacks replay protection/PoP, and permits post-effective-height cancellation; `PQ_KEY_HISTORY_LIMIT = 2` (`:114`) is a count bound shorter than the 48h unbonding/slashing window.
   * Consumer split: `consensus/types.rs:303, 1320, 1654, 2262, 2441`, `consensus/engine.rs:1082, 1093`, `consensus/qc_split.rs:422`, `sharding/block.rs:1296`, `runtime/mev_sync.rs:546` call `pq_key_at_height`; `bridge.rs:618` and `light_client.rs:701` call head-only `get_validator_pq_key`; `staking.rs:3533` (`slash_pq_equivocation`), `runtime/anchors.rs:350`, and `state_engine/apply.rs:3062` read `validator_pq_keys` (head-only).
3. **`remote_signer.rs` is Ed25519-only with split local Falcon signing:**
   * `remote_signer.rs:104-115, 321-338, 449-455, 887-959` is hard-typed to 32B Ed25519 keys and 64B signatures (`ed25519_dalek`).
   * `remote_signer.rs:880-885` documents the HSM GAP: `make_vote_at` (`runtime/consensus_step.rs:1496-1514`), `restamp_for_round` (`runtime/mev_sync.rs:910-915`), and `propose` (`runtime/mev_sync.rs:2203-2213`) call `self.sign_bytes` (Ed25519) and then locally sign Falcon-512 from `self.falcon_key`.
   * `SafetyRecordStore` (`storage.rs:54-254`) is an isolated sled primitive (`docs/specs/05_LOCK_SAFETY_P0.md:46-49`) not yet wired into any signing path, while `persist_vote_watermark_before_broadcast` (`node/consensus_driver.rs:61-95`) runs after signing and treats I/O errors as non-fatal.

---

## 1. Three-Key / Entity Model & Authorization Policy

### 1.1 Entities

1. **`validator_id: ValidatorId` (`[u8; 32]`, `consensus/types.rs:16`) — Immutable Staking & Consensus Anchor**
   * Key in `StakingLedger::validators` (`staking.rs:1211`), `ValidatorSet` (`consensus/types.rs`), `PqRegistry` (`pq_registry.rs:258`), `CnVrfAbortState` (`staking.rs:768`), `jail` (`:1352`), `commission_schedule` (`:1357`), `delegations` (`:1213`), `Vote.voter`, and `Block.proposer`.
   * **Protocol invariant:** Pure 32-byte identifier, **never** a transaction-signing key under FULL-PQ. Remains constant across both `voting_pq_key` rotations and `withdrawal_address` changes so delegations, reward accumulators, CN-VRF debt, and slashing records never re-key.
   * **Derivation for new post-W3 validators (`SysCallRegisterValidator`):**
     `validator_id = BLAKE3("STELL_VAL_ID_V1" || chain_id.to_be_bytes() || withdrawal_address || initial_voting_pubkey)`
     (Prevents front-running/squatting of another operator's `validator_id`; rejects `[0u8; 32]` and existing keys.)
   * **Genesis / pre-W3 validators:** Retain their existing 32-byte `ValidatorId` (migrated per §4.2).

2. **`voting_pq_key: (PqScheme::Falcon512, [u8; 897])` — Hot Consensus Signing Key**
   * Stored on-chain in committed `PqRegistry` keyed by `validator_id` (and mirrored into `StakingLedger::validator_pq_keys` on registration/activation for head consumers).
   * Only `PqScheme::Falcon512` (`0x02`, `post_quantum.rs:154`) is valid; `0x01` (Ed25519), `0x03` (ML-DSA-44, `is_disabled() == true`), and `0x04` (Hybrid) are refused fail-closed (`post_quantum.rs:184-208`).
   * Held in remote HSM/signer (`RemoteSigner` v2, §3) or `./keys/falcon.key` (`node_keys.rs:526-555`).

3. **`withdrawal_address: [u8; 32]` — Cold Staking Control Credential (`PQ1` Falcon-512)**
   * Added to `ValidatorStake` (`staking.rs:878-900`) as `pub withdrawal_address: Option<[u8; 32]>` (non-zero; `None` only on pre-W3 upgraded `ValidatorStakeV1` records until claimed via §4.2).
   * Must be a valid Stellereum `PQ1` account address (`derive_pq_address(PqScheme::Falcon512, &cold_pubkey, &salt)` at `post_quantum.rs:262-269`), authenticated by standard `PQ1` transaction verification (`sharding/transaction.rs:1255-1314`).
   * **Recommended custody:** Distinct Falcon-512 keypair kept offline / in cold wallet, never loaded on the validator node process.

### 1.2 Authorization Matrix: `voting_pq_key` vs `withdrawal_address`

| Action / Surface | `voting_pq_key` (Hot) | `withdrawal_address` (Cold `PQ1` Tx) | Notes & `file:line` |
|---|---|---|---|
| Consensus `Vote` (prevote / precommit) | **ALLOWED** | FORBIDDEN | `consensus/types.rs:1309-1325` (`pq_key_at_height`) |
| Block proposal (`Block.validator_signatures`) | **ALLOWED** | FORBIDDEN | `consensus/types.rs:297-333` |
| µQC / CEC certificates | **ALLOWED** | FORBIDDEN | `consensus/types.rs:2260-2458` |
| CN-VRF v3 commit / reveal | **ALLOWED** | FORBIDDEN | `state_engine/apply.rs:3061-3086`, `runtime/anchors.rs:338-365` |
| PQ MEV DKG / Bridge / Light-client attestations | **ALLOWED** | FORBIDDEN | `runtime/mev_sync.rs:546`, `bridge.rs:618`, `light_client.rs:701` |
| PoP of *new* key inside `Register`/`RotateVotingKey` | **ALLOWED (new key PoP only)** | N/A | Dual-factor: tx signed by `withdrawal_address` + PoP by `new_pubkey` (§2.1) |
| `unbond` (`SysCallUnbond`) | **FORBIDDEN** | **ONLY `withdrawal_address`** | `svm.rs:2278-2300` -> `ctx.sender == v.withdrawal_address` |
| `withdraw` (`SysCallWithdrawSelfBond`) | **FORBIDDEN** | **ONLY `withdrawal_address`** | `svm.rs:2510-2550` -> pays `STAKING_POOL` -> `withdrawal_address` |
| `claim_rewards` (`SysCallClaimRewards`) | **FORBIDDEN** | **ONLY `withdrawal_address`** | `svm.rs:2451-2484` -> pays `REWARDS_POOL` -> `withdrawal_address` |
| `unjail` (`SysCallUnjail`) | **FORBIDDEN** | **ONLY `withdrawal_address`** | `svm.rs:2301-2339`, `state_engine/apply.rs:3891-3936` |
| `rotate_voting_key` (`SysCallRotateVotingKey`) | **FORBIDDEN** | **ONLY `withdrawal_address`** | Compromised hot key cannot rotate itself or lock out cold owner |
| `set_commission` (`SysCallAnnounceCommission` / `Apply`) | **FORBIDDEN** | **ONLY `withdrawal_address`** | Wires `StakingLedger::announce_commission`/`apply_commission` (`staking.rs:1616-1725`) |
| `change_withdrawal` (`SysCallChangeWithdrawal`) | **FORBIDDEN** | **ONLY `withdrawal_address`** | Requires `ctx.sender == current` + PoP of `new_withdrawal_address` (§1.3) |

* **Top-ups (`SysCallStake` / `SysCallStakeWithCommission` on existing `validator`):** Post-W3 activation, calling `SysCallStake`/`SysCallStakeWithCommission` for an **unknown** `validator` reverts (new validators must use `SysCallRegisterValidator` to bind `withdrawal_address` and `voting_pq_key` atomically); calling it for an **existing** `validator` remains `add_bond` (cannot alter `withdrawal_address`, `commission_bps`, or `voting_pq_key`).
* **Legacy `SysCallRotateValidatorKey` (`svm.rs:903-906, 2340-2368`):** Disabled (reverts) at/after `PQ_LIFECYCLE_ACTIVATION_HEIGHT`; `validator_id` is immutable and key replacement uses `SysCallRotateVotingKey` without migrating/laundering staking state (`staking.rs:3666`).
* **Delegators (`SysCallDelegate`, `SysCallBeginUndelegate`, `SysCallUndelegate`, `SysCallClaimDelegatorRewards`):** Remain keyed on the delegator's own `ctx.sender` PQ address (`svm.rs:2369-2450, 2485-2509`), independent of `withdrawal_address` (`ZeroAddress` `[0u8; 32]` guard at `staking.rs:451-461, 1969` stays unchanged).

### 1.3 New Appended SVM `OpCode` Variants (`stellereum/src/svm.rs`)

Per the `OpCode` bincode-discriminant rule (`svm.rs:610-613`), **append** strictly at the end of `enum OpCode` (after `SysCallBindEvmAddress` at `svm.rs:1228`):

1. `SysCallRegisterValidator(Box<RegisterValidatorPayload>)`
   * Fields: `amount: u64`, `commission_bps: u64`, `withdrawal_address: [u8; 32]`, `voting_scheme: u8`, `voting_pubkey: Vec<u8>`, `voting_pop: Vec<u8>`.
   * Rules: `ctx.sender == withdrawal_address` (or caller funds bond and sets `withdrawal_address != [0;32]` + requires `withdrawal_address == ctx.sender` so a third party cannot bind someone else's address without consent); `amount >= ctx.min_validator_bond.max(required_bond_floor_nano())`; `commission_bps <= BPS_DENOMINATOR`; `voting_scheme == 2` (`Falcon512`), `voting_pubkey.len() == 897`, `voting_pop.len() == 666`; PoP verified at `rotation_seq = 0`; derives `validator_id` (§1.1); rejects duplicate `voting_pubkey` or existing `validator_id`.
2. `SysCallRotateVotingKey(Box<RotateVotingKeyPayload>)` (carrier + VM validation; height-checked commit in `apply_pq_registry_ops`, §2).
3. `SysCallChangeWithdrawal(Box<ChangeWithdrawalPayload>)`
   * Fields: `validator_id: [u8; 32]`, `new_withdrawal_address: [u8; 32]`, `new_withdrawal_scheme: u8`, `new_withdrawal_pubkey: Vec<u8>`, `new_withdrawal_salt: [u8; 16]`, `new_withdrawal_pop: Vec<u8>`.
   * Rules: `ctx.sender == current_withdrawal_address` (where `current` is `Some`); `new_withdrawal_address != [0; 32]` and `!= current`; `derive_pq_address(PqScheme::from_id(new_withdrawal_scheme)?, &new_withdrawal_pubkey, &new_withdrawal_salt) == new_withdrawal_address`; `new_withdrawal_pop` (666B) verifies under `new_withdrawal_pubkey` over:
     `b"STELL_WITHDRAWAL_POP_V1" || chain_id.to_be_bytes() || validator_id || current_withdrawal_address || new_withdrawal_address`.
     Prevents irreversible loss to a mistyped/unspendable address.
4. `SysCallClaimWithdrawal(Box<ClaimWithdrawalPayload>)` — one-time migration for pre-W3 validators (`withdrawal_address == None`, §4.2).
5. `SysCallAnnounceCommission { validator: [u8; 32], new_bps: u64 }` — checks `ctx.sender == v.withdrawal_address`; executed at `block.height` in `apply_staking_commission_ops` (`staking.rs:1616-1676`).
6. `SysCallApplyCommission { validator: [u8; 32] }` — permissionless or `withdrawal_address`-callable once `block.height >= pending.effective_height` (`staking.rs:1686-1725`); requiring `ctx.sender == v.withdrawal_address` keeps lifecycle authority uniform.

---

## 2. `RotateVotingKey` Format, PoP & Cross-Module State Machine

### 2.1 Wire Payload & PoP Specification (`pq_registry.rs`, `svm.rs`)

Replace the dead Ed25519 stub (`pq_rotation_announcement_preimage` / `verify_rotation_announcement` at `pq_registry.rs:587-623`) with canonical Falcon-512 PoP verification:

```rust
pub const PQ_KEY_POP_DST: &[u8] = b"STELL_PQ_KEY_POP_V1";

pub struct RotateVotingKeyPayload {
    pub validator_id: [u8; 32],
    pub rotation_seq: u64,       // must equal PqKeyRecord::next_seq (0 reserved for initial register)
    pub new_scheme: u8,          // PqScheme::Falcon512 (0x02) when cancel == false
    pub new_pubkey: Vec<u8>,     // 897 bytes when cancel == false; empty when cancel == true
    pub pop_signature: Vec<u8>,  // 666 bytes when cancel == false; empty when cancel == true
    pub cancel: bool,
}
```

**Canonical PoP Preimage (`pq_voting_key_pop_preimage`):**
```text
PQ_KEY_POP_DST (19B: b"STELL_PQ_KEY_POP_V1")
|| chain_id.to_be_bytes()                 (8B)
|| validator_id                           (32B)
|| withdrawal_address                     (32B)
|| rotation_seq.to_be_bytes()             (8B)
|| scheme.id()                            (1B = 0x02)
|| (pubkey.len() as u16).to_be_bytes()    (2B = 897)
|| pubkey                                 (897B)
```
* **Verification (`verify_voting_key_pop`):**
  1. `PqScheme::from_id(scheme_id)` must return `Ok(PqScheme::Falcon512)` (refuses `0x01`, `0x03`, `0x04`).
  2. `pubkey.len() == FALCON512_PUBKEY_LEN` (`897`) and `pubkey[0] == 0x09` (canonical Falcon-512 header, `post_quantum.rs:1714`).
  3. `pop_signature.len() == FALCON512_SIG_LEN` (`666`).
  4. `verify_pq_signature(PqScheme::Falcon512, pubkey, &preimage, pop_signature)` must return `true`.
* **Replay & Ordering Invariants (`PqKeyRecord` in `pq_registry.rs:230-242`):**
  * Add `pub next_seq: u64` to `PqKeyRecord` (starts at `1` after `register` or `adopt_legacy_key`, which reserve `0`).
  * Both `announce_rotation` and `cancel_rotation` require `rotation_seq == rec.next_seq` and advance `rec.next_seq = rec.next_seq.checked_add(1).ok_or(PqRegistryError::ArithmeticOverflow)?`.
  * `announce_rotation` uses `now_height.checked_add(PQ_ROTATION_DELAY_HEIGHTS).ok_or(PqRegistryError::ArithmeticOverflow)?` (removes `saturating_add` at `pq_registry.rs:416`).
  * **Explicit Cancel (`cancel_rotation`):** Remove cancel-by-reannounce (`pq_registry.rs:407-412`). `cancel_rotation` fails closed unless `rec.pending.is_some()` AND `now_height < pending.effective_height` (`PqRegistryError::RotationAlreadyEffective`), so an already-effective rotation can never be retroactively erased.
  * **Duplicate Key Prohibition:** Reject `register` / `announce_rotation` if `(scheme, pubkey)` equals the validator's own current key (`PqRegistryError::SameKey`) OR equals any other validator's `current` or `pending` key (`PqRegistryError::DuplicateKey`).

### 2.2 Evidence Window & Bounded History (`pq_registry.rs:105-115, 551-556`)

* `PQ_ROTATION_DELAY_HEIGHTS: u64 = 30_000` (`pq_registry.rs:105`, = 7,200 s = 2 h at 240 ms/block).
* `UNBONDING_PERIOD_SECS = 172_800` (`staking.rs:260`, = 48 h). At ~240 ms/block, 48 h = `720_000` heights (= 24 rotations). With `PQ_KEY_HISTORY_LIMIT = 2`, 3 rotations (6 h) already evicted valid equivocation evidence keys inside the unbonding window.
* **W3 Retention Constants (`pq_registry.rs`):**
  * `pub const PQ_EVIDENCE_RETENTION_HEIGHTS: u64 = 720_000;` (covers full 48h unbonding window at 240ms tempo; folded into `FORK_ID_RULES`).
  * `pub const PQ_KEY_HISTORY_MAX_COUNT: usize = 32;` (hard DoS cap; since rotations are rate-limited to 1 per `30_000` heights, at most 24 rotations occur inside `720_000` heights).
* **Pruning rule (`truncate_history(&mut rec.history, now_height)`):**
  Keep every `SupersededPqKey` where `now_height.saturating_sub(entry.superseded_at) < PQ_EVIDENCE_RETENTION_HEIGHTS`, ALWAYS retaining at least the newest `PQ_KEY_HISTORY_LIMIT` (2) entries, and truncating oldest entries only if `history.len() > PQ_KEY_HISTORY_MAX_COUNT`.

### 2.3 Deterministic Pipeline: `pq_registry.rs` ↔ `staking.rs` ↔ `state_engine` ↔ `consensus/rotation.rs` ↔ `storage.rs`

1. **Single Authoritative State Owner (`state_engine/mod.rs`):**
   * Add `pq_registry: Arc<RwLock<crate::pq_registry::PqRegistry>>` to `InMemoryStateEngine` (`state_engine/mod.rs:165-360`), with `pq_registry_read()` and `pq_registry_write()` (bumping `Domain::PqRegistry` + `commitment_generation`).
   * Add `Domain::PqRegistry` to `commitment.rs:123-277` (conditional: writes 0 bytes when `PqRegistry::is_empty()`, preserving pre-W3 genesis KATs; hashes sorted `BTreeMap` entries including `scheme`, `pubkey`, `activated_at`, `next_seq`, `pending`, and `history`).
   * Add conditional `STAKING_WITHDRAWAL_V1` domain at the end of `staking_digest` (`commitment.rs:1270`) when any `ValidatorStake::withdrawal_address.is_some()`.

2. **Exact Execution Order in `apply_block_transition` (`state_engine/apply.rs:2650-2990`):**
   * **Step 0 (pre-tx, before `apply_block_parallel_fees_with_events_at_height`):**
     Run `self.apply_due_pq_rotations(block.height).await` (calls `ledger.pq_apply_due_rotations(&mut pq_reg, block.height)` from `staking.rs:3442-3460`), promoting every `PendingPqRotation` with `effective_height <= block.height` in deterministic `BTreeMap` order and updating `ledger.validator_pq_keys`.
     *Why pre-tx:* At height `H == effective_height`, the new key is already in force; any `cancel` in block `H` fails closed, and a fresh `announce` in block `H` targets the new key.
   * **Step 1 (VM execution in `svm.rs`):**
     `SysCallRegisterValidator`, `SysCallRotateVotingKey`, `SysCallChangeWithdrawal`, `SysCallClaimWithdrawal`, `SysCallAnnounceCommission`, `SysCallApplyCommission` validate `ctx.sender`, payload bounds, scheme, and Falcon PoP signatures against `ctx.staking` (plus read-only `pq_registry` pre-checks). `SysCallChangeWithdrawal` mutates `working_staking` directly via clone-commit; height-dependent ops (`RegisterValidator`, `RotateVotingKey`, `AnnounceCommission`, `ApplyCommission`, `ClaimWithdrawal`) act as verified pre-`Halt` carriers (exact `SysCallUnjail`/`SysCallGovPropose` pattern at `state_engine/apply.rs:3891, 4444`).
   * **Step 5f (`apply_pq_registry_ops(block, &status)` after step 5e):**
     Scans `block.transactions` for `status[i] == true`, stopping at `OpCode::Halt` (`apply_gov_ops` rule at `state_engine/apply.rs:4467-4514`), and atomically executes `register` / `announce_rotation` / `cancel_rotation` / `claim_withdrawal` on `(self.pq_registry_write(), self.staking_write())` with `now_height = block.height`. Refusals log `WARN` and never fail the block.
   * **Post-transition sync (`consensus/rotation.rs`):**
     At the end of `apply_block_transition` (whenever `pq_registry` changed), and on `load_full_state_into` / `ChainState::reorg`, call `consensus::sync_committed_pq_registry(&pq_registry)` which replaces `PQ_COMMITTED_REGISTRY` (`consensus/rotation.rs:52-54`), clears `PQ_VALIDATOR_KEYS` overrides post-W3, and calls `clear_verified_vote_cache()` (`consensus/types.rs:1684`).

3. **Slashing & Consumer Unification:**
   * **`staking.rs:3513-3608` (`slash_pq_equivocation`):** Replace head-only `self.validator_pq_keys.get(&evidence.voter)` (`:3533`) with `self.pq_active_key(&pq_registry, &evidence.voter, evidence.height)` (passed into `slash_pq_equivocation_at_height` from `svm.rs:3242` / `state_engine`). Evidence signed by a superseded key inside `[activated_at, superseded_at)` within `PQ_EVIDENCE_RETENTION_HEIGHTS` slashes identically; evidence outside the window or signed by an unauthoritative key at `evidence.height` fails closed (`InvalidSignature`).
   * **`state_engine/apply.rs:3061-3066` & `runtime/anchors.rs:350-353`:** Resolve `pq_key_at_height(id, height)` **before** `validator_pq_keys`.
   * **`bridge.rs:618`:** Replace `get_validator_pq_key(id)` with `pq_key_at_height(id, attestation_height)` (using committed height from the bridge/consensus context).
   * **`light_client.rs:701`:** Replace `get_validator_pq_key(pubkey)` with `pq_key_at_height(pubkey, self.height)` (and sync light client's height-aware registry from finalized headers/snapshots).
   * **`rpc/state.rs:335-339` & `rpc/reads.rs:2420, 2460`:** Delete isolated `pq_registry_handle()`; `stell_getPqKey` and `stell_getPqRegistryStatus` read directly from `st.engine.pq_registry_read().await` + `st.engine.staking_read().await`, and `stell_getValidatorStatus` (`rpc/reads.rs:2316-2347`) adds `withdrawal_address` and `rotation_seq`.

4. **Snapshot & Replay (`storage.rs`):**
   * **Additive sled tree `"pq_registry"` (`storage.rs:14-39, 850-883`):** Keyed by `height.to_be_bytes()`, storing `bincode(PqRegistry)`, mirroring `"cnvrf_v3"` (`storage.rs:1841-1878`).
   * **Retention:** `prune_pq_registry_below(keep_from)` is invoked from `prune_domains_below` (`storage.rs:1574`) and respects `aux_retained_heights()`.
   * **DomainSnapshot & StakingLedger migration (`storage.rs:2677-3395`):** Add `ValidatorStakeV1` (pre-`withdrawal_address`), `StakingLedgerV6` (pre-W3 `ValidatorStakeV1`), and `DomainSnapshotV9`. `decode_domain_snapshot` tries `DomainSnapshot` -> `DomainSnapshotV9` -> `V8`..`V1`; `decode_domain_snapshot_strict` (`:3381`) accepts ONLY current `DomainSnapshot`.
   * **Restore (`load_full_state_into`, `storage.rs:3506-3659`):** Read `storage.pq_registry_at(height)?`, install into `tmp` (and live `engine`) BEFORE `verify_restored_root(&tmp, height).await?` (`:3634`), then call `consensus::sync_committed_pq_registry`. Because `Domain::PqRegistry` is committed to the state root, a missing/corrupt `"pq_registry"` blob when non-empty fails `verify_restored_root` closed instead of booting with an empty registry.

---

## 3. FULL-PQ Falcon-512 `remote_signer.rs` + Durable Anti-Equivocation

### 3.1 Strictly Typed Falcon-512 `Signer` & `SignerTransport` (`stellereum/src/remote_signer.rs`)

Delete all `ed25519_dalek` imports and 32B/64B Ed25519 constants (`remote_signer.rs:104-115, 321-338, 449-455, 887-1000`):

* **Constants:**
  * `pub const PUBLIC_KEY_LEN: usize = crate::post_quantum::FALCON512_PUBKEY_LEN;` (`897`)
  * `pub const SIGNATURE_LEN: usize = crate::post_quantum::FALCON512_SIG_LEN;` (`666`)
  * `pub const DEFAULT_PUBLIC_KEY_PATH: &str = "/v2/public_key";`
  * `pub const DEFAULT_SIGN_PATH: &str = "/v2/sign";`
* **Typed Request (`ConsensusSignRequest`):**
  ```rust
  #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
  pub enum ConsensusMessageKind { Prevote, Precommit, Proposal }

  #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
  pub struct ConsensusSignRequest {
      pub validator_id: [u8; 32],
      pub chain_id: u64,
      pub shard_id: u32,
      pub height: u64,
      pub round: u32,
      pub kind: ConsensusMessageKind,
      pub target_hash: Option<[u8; 32]>, // Prevote/Precommit target, or Proposal block.compute_hash()
      pub value_id: Option<[u8; 32]>,    // Proposal block.value_id() (Ruleset v6)
      pub preimage: Vec<u8>,             // Exact bytes to sign; verified against structured fields
  }
  ```
* **Domain/Preimage Integrity Check (anti-oracle rule, `remote_signer.rs:49-65, 78-81`):**
  Both `GuardedSigner` (node-side) and the remote signer daemon MUST verify before signing:
  * For `Prevote` / `Precommit`: `preimage == vote_sign_bytes_for_shard_with_chain(chain_id, shard_id, height, round, kind, &target_hash)`.
  * For `Proposal`: `target_hash == Some(h)`, `preimage == h`, `preimage.len() == 32`.
  * Refuses empty/mismatched preimages with `SignerError::SigningFailed(SigningFailureKind::InvalidRequest)`.
* **`PqSigner` & `SignerTransport` Traits:**
  * `PqSigner::scheme(&self) -> PqScheme` (always `Falcon512`)
  * `PqSigner::public_key(&self) -> &[u8; FALCON512_PUBKEY_LEN]`
  * `PqSigner::validator_id(&self) -> [u8; 32]`
  * `PqSigner::sign_consensus(&self, req: &ConsensusSignRequest) -> Result<[u8; FALCON512_SIG_LEN], SignerError>`
  * `SignerTransport::public_key(&self) -> Result<RemotePublicKeyInfo, SignerError>` (`scheme_id == 2`, `897`B pubkey with `pk[0] == 0x09`, `validator_id`)
  * `SignerTransport::sign(&self, req: &ConsensusSignRequest) -> Result<[u8; FALCON512_SIG_LEN], SignerError>`
* **HTTP v2 Wire Protocol (`HttpSignerTransport`):**
  * `GET {base_url}/v2/public_key` → `{"scheme_id": 2, "public_key": "<1794 hex>", "validator_id": "<64 hex>"}`
  * `POST {base_url}/v2/sign` → body `SignRequestV2` (`ConsensusSignRequest` hex/JSON fields) → `{"scheme_id": 2, "signature": "<1332 hex>", "generation": <u64>}`
  * **Transport hardening (`remote_signer.rs:592-605, 746-753`):** Keep timeout (`DEFAULT_TIMEOUT`), `redirects(0)`, `try_proxy_from_env(false)`, `MAX_RESPONSE_BYTES` (`8192`), secret-free `SignerError`, and enforce `https_only(true)` whenever `base_url` is not loopback (`127.0.0.1` / `::1` / `localhost`).
  * **Zero local fallback (`remote_signer.rs:27-33, 470-478`):**
    * `RemoteSigner::new(transport, expected_validator_id, expected_committed_pk)` pins the `897`-byte Falcon-512 public key at startup and verifies `validator_id == expected_validator_id` and (if validator is registered in `PqRegistry`) `pk == active_pk`.
    * Every returned `666`-byte signature is re-verified against `self.pinned_public_key` via `verify_pq_signature(PqScheme::Falcon512, ...)` before leaving `RemoteSigner::sign_consensus`.
    * When `STELL_REMOTE_SIGNER_URL` is configured (`node/bootstrap.rs:787-793`, `node/consensus_driver.rs:286-307`), the node MUST NOT open or load `./keys/falcon.key`. Remove `ValidatorRuntime::key` / `falcon_key` split (`runtime/anchors.rs:18-45, 1047-1100, 3060-3102`, `runtime/consensus_step.rs:1496-1514`, `runtime/mev_sync.rs:910-915, 2203-2213`); all consensus signing goes through one `Arc<dyn PqSigner>` (`GuardedConsensusSigner`).

### 3.2 Durable Anti-Equivocation Contract (`SafetyRecordStore` Alignment)

Both the **node-side `GuardedConsensusSigner`** (using `SafetyRecordStore` in `storage.rs:50-254`) and the **remote signer daemon** (implementing the identical `SafetyRecordStore` state/durability contract on its own disk/HSM NV-storage) enforce the rules from `docs/specs/05_LOCK_SAFETY_P0.md:119-147`:

1. **Identity Binding (`SafetyRecordIdentity` at `storage.rs:53-58`):**
   `SafetyRecordIdentity { validator: validator_id, chain: genesis_hash_or_chain_binding, shard: shard_id }` (distinct per `(validator_id, chain, shard)`).
2. **Persisted Payload (`ConsensusSafetyState` inside `SafetyRecord::payload`):**
   ```rust
   pub struct SignedVoteStamp { pub height: u64, pub round: u32, pub target: Option<[u8; 32]> }
   pub struct SignedProposalStamp { pub height: u64, pub round: u32, pub block_hash: [u8; 32] }
   pub struct ConsensusSafetyState {
       pub height: u64,
       pub locked_round: Option<u32>,
       pub locked_value_id: Option<[u8; 32]>,
       pub last_prevote: Option<SignedVoteStamp>,
       pub last_precommit: Option<SignedVoteStamp>,
       pub last_proposal: Option<SignedProposalStamp>,
   }
   ```
3. **Serialized Check-Persist-Then-Sign Sequence (single mutex/CAS generation):**
   1. `store.load()` — on read/decode/checksum/identity error OR quarantine (`failed == true`), fail closed (`SignerError::SafetyStoreQuarantined`). An absent store (`None`) on a validator with `height > 0` or prior keys requires explicit operator initialization ceremony (`safety_init`), never silent fresh init (`05_LOCK_SAFETY_P0.md:138-146`).
   2. Enforce safety invariants against loaded `ConsensusSafetyState`:
      * `req.height < state.height` -> REFUSE (`SignerError::SafetyViolation`, HTTP `409`).
      * For `Prevote`/`Precommit`: if `last` exists at `req.height`, require `req.round > last.round` (no re-signing same or lower round, preventing post-crash or concurrent-task equivocation and aligning `node/consensus_driver.rs:101-103`). For `Precommit` with `Some(target)`: require `req.value_id` matches `locked_value_id` when locked, or a higher polka unlock is recorded atomically in `ConsensusSafetyState`.
      * For `Proposal`: if `last_proposal` exists at `req.height`, require `req.round > last_proposal.round` (same `(height, round)` second proposal refused — satisfies `proposal_equivocation_offense_rule` at `consensus/engine.rs:523-534`, while allowing Ruleset v6 re-stamps at `r+1`).
   3. Call `store.persist(Some(gen), encode(next_state))` (atomic generation CAS + BLAKE3 checksum + synchronous `db.flush()`).
   4. **On `persist` error:** Quarantine (`failed = true`) and return `Err` — **never sign, never broadcast**.
   5. **Invoke inner `PqSigner::sign_consensus(req)`** (local Falcon key or `RemoteSigner` HTTP v2). If signing fails AFTER durable reservation succeeded, **DO NOT roll back `SafetyRecord`** (`05_LOCK_SAFETY_P0.md:133-134`); return `Err` so the node skips broadcast for that round.

---

## 4. Testnet Migration, Disjoint W3 File Matrix & Mandatory Negative Tests

### 4.1 Ruleset v7, `chain_spec.rs`, and `STELL_*` Migration

* **`stellereum/src/protocol.rs`:**
  * Bump `CONSENSUS_RULESET_VERSION: u32 = 7` (`protocol.rs:101`) and `DOMAIN_SET_VERSION: u32 = 4` (`protocol.rs:106`).
  * Append `crate::pq_registry::PQ_EVIDENCE_RETENTION_HEIGHTS` (and `crate::chain_spec::PQ_LIFECYCLE_ACTIVATION_HEIGHT`) to `FORK_ID_RULES` (`protocol.rs:151-175`), and mix `PQ_KEY_POP_DST` + `b"STELL_WITHDRAWAL_POP_V1"` in `derive_fork_id` (`protocol.rs:199-219`). Mixed v6/v7 nodes fail closed at `negotiate` (`protocol.rs:31-32`).
* **`stellereum/src/chain_spec.rs`:**
  * Add `pub const PQ_LIFECYCLE_ACTIVATION_HEIGHT: u64` (`0` on fresh v7 genesis; `u64::MAX` or explicit cutover height on upgrade chains) to `ChainActivationSchedule` (`chain_spec.rs:202-250`) and `GenesisChainSpec` (`:42-67`). Never read from an env var (`chain_spec.rs:35-38`).
* **`STELL_PEER_PQ_KEYS` (`node/consensus_driver.rs:283, 308-328`) & Genesis Setup (`node/bootstrap.rs`, `runtime/lanes.rs`):**
  * **Fresh v7 genesis (canonical testnet rollout, matching `RULESET_V2..V6`):** `node.yaml` / `GenesisChainSpec` deterministically specifies each genesis validator's `(validator_id, initial_falcon_pubkey, initial_withdrawal_address)`. `fund_genesis` (`runtime/lanes.rs:13-62`) populates `ValidatorStake { withdrawal_address: Some(...), .. }` and calls `ledger.pq_register_key(&mut pq_reg, id, Falcon512, pk, 0, 0)` identically on every node.
  * **Post-activation (`height >= PQ_LIFECYCLE_ACTIVATION_HEIGHT`):** `STELL_PEER_PQ_KEYS` is **ignored with a loud `[WARN]`** (exact pattern of `STELL_PURE_PQ` at `node/consensus_driver.rs:258-260`). Uncommitted env config can never override `PqRegistry`.
  * **In-place snapshot upgrade path (if upgrading an existing v6 store without genesis wipe):**
    1. `DomainSnapshotV9` upgrades pre-W3 `ValidatorStake` rows with `withdrawal_address: None`.
    2. At `PQ_LIFECYCLE_ACTIVATION_HEIGHT`, `apply_block_transition` runs one deterministic adoption pass copying committed `StakingLedger::validator_pq_keys` into `PqRegistry` via `adopt_legacy_key` (`activated_at = 0`, `next_seq = 1`).
    3. While `withdrawal_address == None`, all 7 lifecycle ops (§1.2) fail closed. The operator executes a one-time `SysCallClaimWithdrawal { validator_id, withdrawal_address, voting_sig }` (`ctx.sender == withdrawal_address`, signed by the active `voting_pq_key` over `b"STELL_CLAIM_WITHDRAWAL_V1" || chain_id || validator_id || withdrawal_address`). Once `Some`, `ClaimWithdrawal` is permanently disabled for that validator.

### 4.2 Disjoint File-Ownership Matrix across W3 Echelons (`AGENTS.md §2, §8`)

Every concurrent worker owns a **strictly disjoint** file set; no file appears in two scopes within or across active echelons:

| Echelon | Worker | Owned Files (Strictly Disjoint) | Gate / Prerequisite |
|---|---|---|---|
| **W3-A** | `A1` (Registry & Ruleset) | `stellereum/src/pq_registry.rs`, `stellereum/src/protocol.rs`, `stellereum/src/chain_spec.rs` | Starts after W0/W2 |
| **W3-A** | `A2` (Remote Signer v2) | `stellereum/src/remote_signer.rs`, `stellereum/tests/remote_signer_tests.rs` | Starts after W0/W2 (parallel with `A1`) |
| **W3-B** | `B1` (Staking & Commit) | `stellereum/src/staking.rs`, `stellereum/src/commitment.rs` | Depends on `W3-A` |
| **W3-B** | `B2` (Storage & Snapshots) | `stellereum/src/storage.rs` | Depends on `W3-A` (or sequential after `B1` if `ValidatorStakeV1` moves `ValidatorStake` layout) |
| **W3-C** | `C1` (VM, Mempool, Engine) | `stellereum/src/svm.rs`, `stellereum/src/mempool.rs`, `stellereum/src/state_engine/{mod,apply,types}.rs` | Depends on `W3-B` |
| **W3-C** | `C2` (Consensus & Readers) | `stellereum/src/consensus/rotation.rs`, `stellereum/src/bridge.rs`, `stellereum/src/light_client.rs` | Depends on `W3-B` (parallel with `C1`) |
| **W3-C** | `C3` (Runtime Signing) | `stellereum/src/runtime/{mod,anchors,consensus_step,mev_sync,lanes}.rs` | Depends on `W3-A2` + `W3-B` (parallel with `C1`/`C2`) |
| **W3-C** | `C4` (Node, RPC, CLI) | `stellereum/src/node/{bootstrap,consensus_driver,sync}.rs`, `stellereum/src/rpc/{state,reads}.rs`, `stellereum/src/cli/{args,tx_builders}.rs` | Depends on `W3-C1/C2/C3` |
| **W3-D** | `D1` (Test & Gate Closeout) | `stellereum/tests/{pq_registry_tests,pq_equivocation_report_tests,staking_ledger_migration_tests,node_bootstrap_tests,pq_validator_lifecycle_w3_tests}.rs` | Depends on `W3-C`; runs full gate + `consensus_liveness_harness` |

*(Note: Because `B1` modifies `ValidatorStake` fields used by `B2`'s `ValidatorStakeV1`, run `B1` before `B2` or place `ValidatorStakeV1` in `storage.rs` right after `B1` merges.)*

### 4.3 Mandatory Negative & Boundary Tests

Every W3 echelon must land deterministic negative tests (no mocked passes, `AGENTS.md §3`):

1. **Key-Separation & Auth (`W3-C1`, `W3-D1`):**
   * `voting_pq_key` submits `SysCallUnbond`, `SysCallWithdrawSelfBond`, `SysCallClaimRewards`, `SysCallUnjail`, `SysCallRotateVotingKey`, `SysCallAnnounceCommission`, `SysCallApplyCommission`, or `SysCallChangeWithdrawal` -> **reverted**, state unchanged.
   * Outsider `ctx.sender` submits any of the 7 ops -> **reverted**.
   * Unclaimed `withdrawal_address == None` attempts any of the 7 ops -> **reverted**.
   * `SysCallClaimWithdrawal` with wrong `voting_pq_key` sig, wrong `chain_id`, or when `withdrawal_address` is already `Some` -> **reverted**.
   * `SysCallChangeWithdrawal` with `[0u8; 32]`, `new == current`, or invalid `new_withdrawal_pop` -> **reverted**.
   * Legacy `SysCallRotateValidatorKey` at `height >= PQ_LIFECYCLE_ACTIVATION_HEIGHT` -> **reverted**.
2. **`RotateVotingKey` PoP & State Machine (`W3-A1`, `W3-C1`, `W3-D1`):**
   * PoP signed by old `voting_key` or wrong key (not `new_pubkey`) -> **rejected**.
   * Cross-chain PoP (`chain_id` mismatch), cross-validator PoP, or cross-`withdrawal_address` PoP -> **rejected**.
   * Replay of consumed `rotation_seq` or out-of-order `rotation_seq != next_seq` -> **rejected**.
   * Duplicate `new_pubkey` already registered/pending for another validator, disabled scheme (`0x01`/`0x03`/`0x04`), wrong key/sig length, or `now_height + PQ_ROTATION_DELAY_HEIGHTS` overflow near `u64::MAX` -> **rejected** (`ArithmeticOverflow`).
   * `cancel_rotation` at `now_height == effective_height` or `> effective_height`, or when nothing pending -> **rejected** (`RotationAlreadyEffective` / `NoPendingRotation`).
   * Boundary `H-1 / H / H+1`: votes, proposals, µQCs, and bridge/light-client attestations signed by old key pass at `H-1` and fail at `H`; new key fails at `H-1` and passes at `H`.
   * Post-`OpCode::Halt` `SysCallRotateVotingKey` or reverted tx carrying valid rotation -> `PqRegistry` and `next_seq` unchanged.
3. **Real Slashing Evidence Window & Consumers (`W3-B1`, `W3-C2`, `W3-D1`):**
   * Chain of 5 rotations inside `PQ_EVIDENCE_RETENTION_HEIGHTS` (720,000 heights): `slash_pq_equivocation_at_height` against the 1st key STILL resolves and burns 5% + debits `STAKING_POOL`.
   * Evidence older than `PQ_EVIDENCE_RETENTION_HEIGHTS` (pruned) -> fails closed (`InvalidSignature`), never falls back to head key.
   * `bridge::verify_quorum_signatures` and `light_client::verify_validator_quorum` reject stale post-rotation keys and accept historical pre-rotation heights.
4. **Snapshot, Replay & Cache Invalidation (`W3-B2`, `W3-C2`, `W3-D1`):**
   * `DomainSnapshotV8` decodes via `decode_domain_snapshot` (`withdrawal_address == None`); `decode_domain_snapshot_strict` refuses legacy bytes.
   * Missing/corrupted `"pq_registry"` tree entry with non-empty committed registry -> `verify_restored_root` fails closed.
   * Reorg past a rotation block + replay -> `PqRegistry`, `consensus::rotation`, and `VERIFIED_VOTE_CACHE` agree (`old` key cache entry never validates post-`H` vote).
5. **FULL-PQ `RemoteSigner` & `SafetyRecordStore` (`W3-A2`, `W3-C3`, `W3-D1`):**
   * `/v2/public_key` returning 32B Ed25519 key, `scheme_id != 2`, bad header byte `!= 0x09`, wrong length, or mismatched `validator_id` -> startup fails closed.
   * `/v2/sign` returning 64B sig, wrong length, foreign key's Falcon sig, HTTP 409/500, or timeout -> returns `Err` with **zero local fallback** even when `./keys/falcon.key` is present.
   * Conflicting `(height, round, Prevote/Precommit)` or conflicting `(height, round, Proposal)`, or lower `(height, round)` than persisted watermark -> refused on both node `SafetyRecordStore` and remote signer.
   * Injected `SafetyRecordStore` read/decode/write/flush error -> quarantines all handles (`requires recovery`), produces zero signature, and a failed remote sign after durable reservation does NOT roll back the reservation.
   * `preimage` mismatching structured `ConsensusSignRequest` fields -> refused (no arbitrary signing oracle).
6. **Testnet `STELL_*` & Handshake Gate (`W3-A1`, `W3-C4`, `W3-D1`):**
   * `STELL_PEER_PQ_KEYS` set post-activation -> ignored with WARN, cannot inject/override `PqRegistry`.
   * Ruleset v6 vs v7 peer handshake -> refused on `FORK_ID` mismatch.
