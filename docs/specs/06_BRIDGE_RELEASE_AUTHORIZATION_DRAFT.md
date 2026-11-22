# 06 — BRIDGE-FIX-FULL: Release Authorization, Finality-Bound Headers, Challengeable Evidence & Height-Indexed PQ Quorums

**Status: BRIDGE-FIX-FULL IMPLEMENTATION SPECIFICATION (supersedes the initial design draft; pending coordinated activation and Ruleset/FORK_ID bump).**
This specification anchors every required change to canonical `stellereum/src/` and `stellereum/tests/` (`file:line` verified against current workspace). Changes to `BridgeIntent` / `BridgeState`, `commitment.rs`, signature domains, `protocol.rs` / `FORK_ID`, and `chain_spec.rs` remain subject to `AGENTS.md §7` (spec + audit note + full frozen-core gate).

---

## 0. Verified Audit Baseline (4 Open Bridge Issues)

1. **Unauthenticated bare `BridgeIntent::Release { req_id }` (`stellereum/src/bridge.rs:932-951, 1484-1490`):**
   * `BridgeState::plan` passes `Release { req_id }` straight to `TeleportBridgeEngine::finalize_withdrawal`, which checks only `pending_withdrawals.get_mut(&req_id)`, `!req.executed`, and `now >= req.unlock_at`, then flips `req.executed = true`.
   * Neither `plan` nor `finalize_withdrawal` checks transaction `payer`, a relayer/validator quorum, an external payout receipt, or cancellation evidence.
   * `Refund { req_id }` (`bridge.rs:956-984, 1491-1502`) requires `req.sender == payer`, `!req.executed`, and `now >= req.unlock_at + REFUND_GRACE_SECS`. Thus an outsider can submit a bare `Release { req_id }` right at/after `unlock_at` (including immediately at `now` for `< LARGE_WITHDRAWAL_THRESHOLD_NANO`, where `unlock_at == now`) and permanently destroy the sender's refund path without proving any external payout (`stellereum/tests/bridge_authorization_p0_regression.rs:21-69`).
   * Conversely, `MultisigRelayer` / `TonMultisigReleaseOrder` / `EvmReleaseOrder` (`bridge.rs:1912-2234`) live only in an isolated off-chain model with no consensus caller, no `req_id` / `chain_id` binding, and an unbounded refund-vs-late-payout double-spend window (audit B3 / F-G).
2. **Unsigned `finalized_seqno` / `finalized_number` / `finalized_slot` & adapter-mixing surface (`stellereum/src/bridge_adapters.rs:227-250, 644-691, 754-766, 861-885, 974-991`):**
   * `check_header` verifies quorum signatures ONLY over `StoredHeader::signing_message()` (`b"STELL_BRIDGE_HEADER_V1" || chain_tag || height || prev_hash || tx_root`).
   * `finalized_seqno` (`TonCell`), `finalized_number` (`EvmReceipt`), and `finalized_slot` (`SolanaTx`) are excluded from the signed preimage. Anyone holding a shallow (`depth = 0`) quorum-signed header can inflate `finalized_*` by `min_confirmations` (`12` / `64` / `32` / `32`) and make `check_depth` accept an unfinalized proof (`bridge_authorization_p0_regression.rs:117-220`).
   * Furthermore, `StoredHeader::signing_message()` does not bind Stellereum `chain_id` or an explicit `AdapterKindTag` (`TonCell` vs `EvmReceipt` vs `SolanaTx`), and `evm_receipt_encoding` (`bridge_adapters.rs:169-173`) silently maps non-EVM chains to `0x00u8` instead of failing closed.
3. **Evidence-path deposits are unchallengeable (`stellereum/src/bridge.rs:1461-1468, 1513-1517`):**
   * `BridgeState::plan` records every `DepositProof`-admitted deposit with `via_quorum: false` (`bridge.rs:1465`) — **even for `DepositEvidence::QuorumAttested`** — and `Challenge` refuses `!record.via_quorum` (`bridge.rs:1513`, pinned by `stellereum/tests/bridge_dispute_tests.rs:709-753`).
   * Today, `TonCell`, `EvmReceipt`, and `SolanaTx` do **not** run a trustless foreign light client or ZK verifier (`bridge_adapters.rs:40-65`): their header root and finalized head are attested **by the same 2/3 validator quorum** (`check_header`). Leaving `DepositProof` unchallengeable lets a compromised or mistaken 2/3 quorum bypass the optimistic challenge layer ("one honest observer suffices") simply by submitting `DepositProof` instead of `Attest`.
4. **Bridge quorum reads uncommitted process-local map instead of committed height-indexed `PqRegistry` (`stellereum/src/bridge.rs:618`, `stellereum/src/consensus/rotation.rs:8-76, 109-112`):**
   * `distinct_falcon_signers` (`bridge.rs:598-633`) resolves keys via `crate::consensus::get_validator_pq_key(id)` (`bridge.rs:618`), which reads the uncommitted, process-local `PQ_VALIDATOR_KEYS` `HashMap` (`consensus/rotation.rs:8-10, 109-112`) rather than the deterministic, committed height-indexed `PqRegistry` (`pq_registry.rs:256-517`, `staking.rs:3467-3477`).
   * Additionally, `stellereum/examples/vuln_hunt5.rs:690-702` still signs raw `msg` with classical `ed25519_dalek` rather than Falcon-512 over `MultisigRelayer::release_signing_message`.

---

## 1. Domain-Separated `StoredHeader` Signing, Finality Binding, Adapter Isolation & `BRIDGE_V2_ACTIVATION_HEIGHT`

### 1.1 Canonical V2 Header Signing Preimage (`stellereum/src/bridge_adapters.rs`)

Keep `StoredHeader` (`chain, height, prev_hash, tx_root`) and `DepositEvidence` bincode field layouts backward-compatible so pre-activation blocks and `HeaderStore` entries deserialize unchanged. Add an explicit adapter discriminant and V2 preimage builder on `StoredHeader`:

```rust
pub const BRIDGE_HEADER_SIGN_DOMAIN_V2: &[u8] = b"STELL_BRIDGE_HEADER_V2"; // 22 bytes

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterKindTag {
    TonCell = 0x01,
    EvmReceipt = 0x02,
    SolanaTx = 0x03,
}

impl StoredHeader {
    /// V2 quorum preimage: binds Stellereum network (`chain_id`), adapter variant,
    /// foreign chain tag, header fields, AND the attested finalized head.
    pub fn signing_message_v2(
        &self,
        chain_id: u64,
        adapter_kind: AdapterKindTag,
        finalized_head: u64,
    ) -> Vec<u8> {
        let mut b = Vec::with_capacity(22 + 8 + 1 + 1 + 8 + 32 + 32 + 8); // 112 bytes
        b.extend_from_slice(BRIDGE_HEADER_SIGN_DOMAIN_V2);
        b.extend_from_slice(&chain_id.to_be_bytes());
        b.push(adapter_kind as u8);
        b.push(Self::chain_tag(self.chain));
        b.extend_from_slice(&self.height.to_be_bytes());
        b.extend_from_slice(&self.prev_hash);
        b.extend_from_slice(&self.tx_root);
        b.extend_from_slice(&finalized_head.to_be_bytes());
        b
    }
}
```

**Binding guarantees (112 bytes, fixed-width big-endian, zero ambiguity):**
* `BRIDGE_HEADER_SIGN_DOMAIN_V2` separates V2 header attestations from V1 (`STELL_BRIDGE_HEADER_V1`), deposit claims, deposit retractions (`STELL_BRIDGE_DEPOSIT_FAILURE_V1`), release receipts (`STELL_BRIDGE_RELEASE_RECEIPT_V2`), and consensus votes/QCs.
* `chain_id` prevents cross-network signature replay (devnet/testnet/mainnet).
* `adapter_kind` (`0x01` / `0x02` / `0x03`) binds signatures to the exact adapter variant (`TonCell` uses `finalized_seqno`, `EvmReceipt` uses `finalized_number`, `SolanaTx` uses `finalized_slot`).
* `StoredHeader::chain_tag(self.chain)` (`0x54` TON, `0x41` Arbitrum, `0x45` Ethereum, `0x53` Solana) prevents cross-chain transplant (e.g. Arbitrum vs Ethereum).
* `finalized_head` is signed by the 2/3 distinct Falcon-512 quorum alongside `header`: mutating `finalized_seqno`, `finalized_number`, or `finalized_slot` invalidates the quorum signature immediately inside `check_header`.

### 1.2 Adapter-Mixing Protection & Shape Hardening

Enforce all of the following fail-closed checks across `bridge_adapters.rs` and `bridge.rs`:
1. **`check_header_at_height` signature & binding:**
   * Replace internal `check_header(...)` (`bridge_adapters.rs:644-665`) with:
     `check_header_at_height(adapter_kind, adapter_chain, header, finalized_head, header_signatures, evidence_name, validators, chain_id, block_height, attestation_height, pq_keys)`.
   * Assert `header.chain == adapter_chain` AND `claim.chain == adapter_chain` in every adapter (`TonAdapter`, `EvmAdapter`, `SolanaAdapter`) AND in `verify_evidence_at_height` before any cryptographic work.
2. **Strict EVM adapter pinning (`bridge_adapters.rs:162-182, 819-829, 1112-1123`):**
   * `EvmAdapter::try_new(chain, min_confirmations) -> Result<Self, String>` (and `EvmAdapter::new` asserting `Ethereum | Arbitrum`) + `verify_deposit` must refuse any `chain` not in `{SupportedChain::Ethereum, SupportedChain::Arbitrum}` fail-closed.
   * `evm_receipt_encoding` / `verify_deposit` must never accept `_ => 0x00u8`; fail closed on non-EVM chains in `EvmAdapter::verify_deposit` before constructing `expected`.
3. **Finality & shape gates (`bridge_adapters.rs:555-617, 670-691`):**
   * Keep `check_depth` strict (`if header_height > finalized { Err(...) }`, `finalized - header_height >= min_confirmations`).
   * In `DepositEvidence::validate_shape()`, also reject `header.height > finalized_*` early and verify `BridgeIntent::Attest { signatures, .. }` in `BridgeIntent::validate()` (`bridge.rs:411-419`) enforces `1 <= signatures.len() <= bridge_adapters::MAX_HEADER_SIGNATURES` (`1024`), closing the unbounded `Attest` DoS vector (`BRIDGE_THREAT_MODEL.md:1009-1016`).
   * Keep `DepositEvidence::ZkProofPlaceholder` rejected fail-closed at both `validate_shape()` and `verify_evidence_at_height()`.

### 1.3 `BRIDGE_V2_ACTIVATION_HEIGHT` & `H-1 / H / H+1` Boundary Rule

* **Single source of truth (`stellereum/src/bridge.rs`, mirrored in `chain_spec.rs` & `protocol.rs`):**
  * Define `pub const BRIDGE_V2_ACTIVATION_HEIGHT: u64 = 0;` on a fresh Ruleset v7/v8 genesis (matching `GOV_OPS_ACTIVATION_HEIGHT = 0`, `XPC_ACTIVATION_HEIGHT = 0`, `PROPOSAL_EQUIVOCATION_ACTIVATION_HEIGHT = 0`), OR explicit cutover height `H` when upgrading an existing chain in-place.
  * Provide `pub fn bridge_v2_activation_height() -> u64` and `pub fn bridge_v2_active_at(height: u64) -> bool { height >= bridge_v2_activation_height() }`, plus a `#[cfg(any(test, debug_assertions))]` `thread_local!` override `set_bridge_v2_activation_override(Option<u64>)` (exact pattern of `zkml_attestation.rs:149-184` and `governance.rs:144-174`).
  * **Never** infer activation from wall clock (`now_secs`), environment variables, or binary version.
  * Register `BRIDGE_V2_ACTIVATION_HEIGHT` in `ChainActivationSchedule` (`chain_spec.rs:255`) and fold `BRIDGE_V2_ACTIVATION_HEIGHT` + `BRIDGE_HEADER_SIGN_DOMAIN_V2` + `BRIDGE_RELEASE_RECEIPT_DOMAIN_V2` into `FORK_ID_RULES` / `derive_fork_id` (`protocol.rs:151-219`), bumping `CONSENSUS_RULESET_VERSION` and `DOMAIN_SET_VERSION` so mixed-version peers fail closed at `protocol::negotiate`.
* **Exact `H-1 / H / H+1` Transition Matrix (where `H = bridge_v2_activation_height()`):**

| Surface | Height `H - 1` (Pre-Activation) | Height `H` and `H + 1` (Post-Activation) |
|---|---|---|
| `StoredHeader` signature | V1 `header.signing_message()` accepted for historical replay | **ONLY** V2 `signing_message_v2(chain_id, adapter_kind, finalized_head)` accepted; V1 **rejected fail-closed** (no dual-accept fallback) |
| Bare `BridgeIntent::Release { req_id }` | Legacy `finalize_withdrawal` (historical replay only) | **REJECTED fail-closed** unless paired with valid `BridgeIntent::ReleaseProof` |
| `Challenge` on `DepositProof` deposit | Legacy `!record.via_quorum` refusal | **ALLOWED** for all quorum-anchored deposits (`QuorumAttested`, `TonCell`, `EvmReceipt`, `SolanaTx`) within `CHALLENGE_MAX_AGE_SECS` |
| Quorum PQ key lookup | Legacy `get_validator_pq_key` fallback only if `PqRegistry` has no record | **ONLY** height-indexed committed `PqRegistry` (`PqKeyLookup::pq_key_at(id, attestation_height)`); zero read of global `PQ_VALIDATOR_KEYS` |

---

## 2. Safe `Release` + `Refund` + Payout Receipt Protocol & Evidence-Path Challenge Closure

### 2.1 Wire Format (`BridgeIntent` Discriminant Stability)

`BridgeIntent` (`stellereum/src/bridge.rs:233-377`) is bincode-serialized inside signed payloads; `deposit_proof_variant_keeps_legacy_discriminants_stable` (`bridge.rs:2684-2739`) pins discriminants `0..=7`.
**Keep `BridgeIntent::Release { req_id: u64 }` at discriminant `3` untouched, and append variant `8` strictly at the end:**

```rust
// APPENDED variant — strictly LAST (discriminant 8):
ReleaseProof {
    req_id: u64,
    receipt: Box<ReleaseReceiptEvidence>,
},
```

**`ReleaseReceiptEvidence` structure & canonical preimage (`bridge.rs` / `bridge_adapters.rs`):**

```rust
pub const BRIDGE_RELEASE_RECEIPT_DOMAIN_V2: &[u8] = b"STELL_BRIDGE_RELEASE_RECEIPT_V2";
/// Safety buffer before `refund_at = unlock_at + REFUND_GRACE_SECS`:
/// external release orders MUST expire at or before `refund_at - PAYOUT_SAFETY_MARGIN_SECS`
/// (24h - 4h = 20h window for relayers, 4h quiet/finality margin before native refund).
pub const PAYOUT_SAFETY_MARGIN_SECS: u64 = 4 * 3600;
/// Maximum age (in Stellereum blocks) between `attestation_height` and `block_height`.
/// Bounded by `PQ_EVIDENCE_RETENTION_HEIGHTS` (720,000 blocks per W3 spec §2.2).
pub const MAX_BRIDGE_ATTESTATION_AGE_HEIGHTS: u64 = crate::pq_registry::PQ_EVIDENCE_RETENTION_HEIGHTS;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseReceiptEvidence {
    pub req_id: u64,
    pub target_chain: SupportedChain,
    pub target_address: String,
    pub amount: u64,
    /// Non-zero foreign-chain payout transaction hash (unique across all releases).
    pub external_tx_hash: [u8; 32],
    /// Foreign finalized block/seqno/slot observed past chain finality depth.
    pub finalized_head: u64,
    /// Committed Stellereum height whose active PQ keys signed this receipt.
    pub attestation_height: u64,
    /// Distinct Falcon-512 validator signatures over `release_receipt_signing_message_v2`.
    pub signatures: Vec<([u8; 32], Vec<u8>)>,
}
```

Canonical receipt signing preimage (`release_receipt_signing_message_v2(chain_id, &receipt)`):
```text
BRIDGE_RELEASE_RECEIPT_DOMAIN_V2 (31B: b"STELL_BRIDGE_RELEASE_RECEIPT_V2")
|| chain_id.to_be_bytes()                 (8B)
|| receipt.req_id.to_be_bytes()           (8B)
|| StoredHeader::chain_tag(receipt.target_chain) (1B)
|| (receipt.target_address.len() as u32).to_be_bytes() (4B)
|| receipt.target_address.as_bytes()
|| receipt.amount.to_be_bytes()           (8B)
|| receipt.external_tx_hash               (32B)
|| receipt.finalized_head.to_be_bytes()   (8B)
|| receipt.attestation_height.to_be_bytes() (8B)
```
*Note: `BridgeIntent::validate()` (`bridge.rs:385`) enforces `receipt.external_tx_hash != [0u8; 32]`, `!receipt.target_address.trim().is_empty()`, `receipt.amount > 0`, and `1 <= receipt.signatures.len() <= MAX_HEADER_SIGNATURES`.*

### 2.2 Committed State Machine (`BridgeState`, `BridgeStateV3`, `commitment.rs`, `accounts.rs`)

Extend `BridgeState` (`bridge.rs:1038-1077`) with three deterministic `BTree*` fields (sorted containers only, `PROTOCOL.md I2`):
```rust
pub struct ReleaseReceiptRecord {
    pub target_chain: SupportedChain,
    pub target_address: String,
    pub amount: u64,
    pub external_tx_hash: [u8; 32],
    pub finalized_head: u64,
    pub attestation_height: u64,
    pub settled_at: u64,
}

// Appended to BridgeState:
pub release_receipts: BTreeMap<u64, ReleaseReceiptRecord>, // req_id -> verified payout receipt
pub processed_payout_txs: BTreeSet<[u8; 32]>,              // external_tx_hash replay guard
pub refunded_withdrawals: BTreeSet<u64>,                   // req_id refund tombstone
```
* **`BridgeState::is_empty()` (`bridge.rs:1210`):** Include `self.release_receipts.is_empty() && self.processed_payout_txs.is_empty() && self.refunded_withdrawals.is_empty()`. An untouched domain still writes zero bytes to `commitment_digest`, leaving all genesis KATs unchanged.
* **Snapshot migration (`bridge.rs`, `state_engine/accounts.rs:2209-2246`):** Introduce `BridgeStateV3` matching the exact current `BridgeState` layout; `restore_bridge` tries `BridgeState` -> `BridgeStateV3` -> `BridgeStateV2` -> `BridgeStateV1` with loud `tracing::warn!` on legacy upgrade (`release_receipts`/`processed_payout_txs`/`refunded_withdrawals` start empty; no historical `executed = true` flag is retroactively elevated to a verified `ReleaseReceiptRecord`).
* **Commitment (`stellereum/src/commitment.rs:1497-1565`):** Append deterministic `bridge_release_receipts`, `bridge_processed_payout_txs`, and `bridge_refunded_withdrawals` loops at the end of `bridge_digest`.

### 2.3 Transition Rules (`Release`, `Refund`, External Orders & Honest Closure of `outsider_release_cannot_destroy_the_senders_refund_path`)

1. **Pairing & `BridgeIntent::Release { req_id }` at `block_height >= BRIDGE_V2_ACTIVATION_HEIGHT`:**
   * `BridgeState::plan_at_height` indexes all `BridgeIntent::ReleaseProof { req_id, receipt }` intents in the payload into `BTreeMap<u64, Vec<ReleaseReceiptEvidence>>` (same pattern as `Attest` / `DepositProof`). A lone `ReleaseProof` with no `Release` is inert and mutates nothing.
   * On `BridgeIntent::Release { req_id }`:
     1. Look up `req = engine.pending_withdrawals.get(req_id)`: must exist (if `refunded_withdrawals.contains(req_id)`, return explicit `"Withdrawal already refunded"`).
     2. Enforce `!req.executed` and `now >= req.unlock_at`.
     3. **No bare Release:** If no `ReleaseProof` is paired for `*req_id`, **FAIL CLOSED** (`Err("bridge release rejected: verified payout receipt required")`) — regardless of whether `payer` is an outsider, the original `sender`, or a validator.
     4. Verify at least one paired `ReleaseReceiptEvidence` for `*req_id`:
        * `receipt.req_id == *req_id`, `receipt.target_chain == req.target_chain`, `receipt.target_address == req.target_address`, `receipt.amount == req.amount`.
        * `receipt.external_tx_hash != [0u8; 32]` AND `!processed_payout_txs.contains(&receipt.external_tx_hash)`.
        * `receipt.attestation_height <= block_height` AND `block_height.saturating_sub(receipt.attestation_height) <= MAX_BRIDGE_ATTESTATION_AGE_HEIGHTS`.
        * `verify_quorum_signatures_at_height(&release_receipt_signing_message_v2(chain_id, receipt), &receipt.signatures, validators, receipt.attestation_height, pq_keys)` passes `>= bridge_threshold(validators.len())` (with `validators.is_empty()` failing closed!).
     5. Commit atomically: `req.executed = true`, insert `receipt.external_tx_hash` into `processed_payout_txs`, and insert `(*req_id, ReleaseReceiptRecord { ... })` into `release_receipts`. Any error aborts `plan_at_height` with zero partial state mutation.

2. **`BridgeIntent::Refund { req_id }` & External-Leg Exclusion:**
   * `Refund` requires: `req` exists in `pending_withdrawals`, `!req.executed`, `!refunded_withdrawals.contains(req_id)`, `req.sender == payer`, and `now >= req.unlock_at.saturating_add(REFUND_GRACE_SECS)`.
   * On success: remove `req_id` from `pending_withdrawals`, insert `req_id` into `refunded_withdrawals` tombstone, decrement `hourly_withdrawn` by `req.amount`, and emit `BridgeEffect::Unpark { recipient: payer, amount }`.
   * **External order synchronization (`TonMultisigReleaseOrder`, `EvmReleaseOrder`, `MultisigRelayer` in `bridge.rs:1912-2234`):**
     * Extend `TonMultisigReleaseOrder` and `EvmReleaseOrder` to carry `req_id: u64` and `stellereum_chain_id: u64` inside their `signing_message()` preimages, and verify signatures via `PqKeyLookup` (`count_signers_at_height`).
     * Enforce `order.expires_at <= req.unlock_at.saturating_add(REFUND_GRACE_SECS).saturating_sub(PAYOUT_SAFETY_MARGIN_SECS)` (`20h` max payout authorization window vs `24h` refund unlock — `4h` quiet/finality margin exceeding TON/Ethereum/Arbitrum/Solana finality!).
     * Relayer daemons MUST NOT sign or broadcast any order if committed state has `executed == true`, `refunded_withdrawals.contains(req_id)`, or `now >= order.expires_at`.
     * *Why this guarantees at-most-one outcome without sacrificing sender liveness:*
       - If relayers never pay or go offline, the sender can ALWAYS `Refund` at `refund_at = unlock_at + REFUND_GRACE_SECS` (1/3+1 offline relayers cannot hold user funds hostage).
       - If relayers DO pay before `expires_at`, the `4h` margin ensures external finality completes before `refund_at`, and ANY observer/relayer/user can submit `Release + ReleaseProof` to set `executed = true` (even at `now >= refund_at` if `Refund` has not yet landed), atomically excluding `Refund`.
       - Because `refunded_withdrawals` is retained on-chain, a late `ReleaseProof` after `Refund` fails loudly with `"Withdrawal already refunded"` instead of silently mutating absent state.

3. **How this honestly closes `bridge_authorization_p0_regression::outsider_release_cannot_destroy_the_senders_refund_path` after `unlock_at`:**
   * In `stellereum/tests/bridge_authorization_p0_regression.rs:21-69`, `amount = 1_000_000_000` (`< LARGE_WITHDRAWAL_THRESHOLD_NANO`), so `unlock_at == now` (`1_760_000_000`). Thus `outsider` submits `BridgeIntent::Release { req_id: 0 }` **at `now >= unlock_at`**, with `validators = &[]` and zero payout evidence.
   * Under `BRIDGE-FIX-FULL`, `parked.plan(&[BridgeIntent::Release { req_id: 0 }], &[], outsider, now)` (active at `height = 0 >= BRIDGE_V2_ACTIVATION_HEIGHT`) **fails closed** (`attempt.is_err()`) because no verified `ReleaseProof` is present (and `validators = &[]` can never form a receipt quorum).
   * `parked.pending_withdrawals[&0].executed` remains `false`, so `sender` executes `Refund { req_id: 0 }` at `refund_at = now + REFUND_GRACE_SECS` and receives `BridgeEffect::Unpark { recipient: sender, amount }`.
   * The existing assertion in `bridge_authorization_p0_regression.rs:65-68` passes **without modifying or weakening the test** (`AGENTS.md §3`). In addition, `BRIDGE-FIX-FULL` adds post-`unlock_at` tests with a real 3-validator Falcon set (`validators.len() == 3`) verifying that: (a) bare `Release` by `outsider` OR `sender` fails, (b) `Release + ReleaseProof` with mismatched `req_id` / `amount` / `target_address` / sub-quorum fails, and (c) only a genuine 2/3 Falcon `ReleaseProof` finalizes `executed = true` and blocks subsequent `Refund`.

### 2.4 Evidence-Path Deposit `Challenge` & `Resolve` Closure (`bridge.rs:1461-1468, 1513-1517, 1638-1684`)

* **`Deposit` evidence arm (`bridge.rs:1461-1468`):**
  * When admitted via `DepositEvidence::QuorumAttested`, set `via_quorum: true` (it is pure testimony).
  * For `TonCell`, `EvmReceipt`, and `SolanaTx`: keep `via_quorum: false` in `DepositRecord` for telemetry (`native_api.rs:1788`), OR document clearly that all three are currently **quorum-anchored** (`check_header` trusts 2/3 validators, not a foreign light client).
* **`Challenge` arm (`bridge.rs:1513-1517`):**
  * At `block_height >= BRIDGE_V2_ACTIVATION_HEIGHT`, **remove** the `if !record.via_quorum { return Err(...) }` bypass! Every admitted deposit (whether `Attest` or `DepositProof`) is challengeable within `CHALLENGE_MAX_AGE_SECS` while `!record.disputed`, until a future trustless ZK/light-client verifier (with no validator-quorum header dependency) is explicitly enabled.
* **`Resolve` truth-grading precedence (`bridge.rs:1638-1684`):**
  * While `TonCell`, `EvmReceipt`, and `SolanaTx` remain quorum-anchored, an explicit quorum retraction (`verify_quorum_retraction_at_height`) MUST **not** be defeated by replaying the same quorum-signed `StoredHeader` (`RETRACTION` outranks quorum-anchored `DepositProof` and `QuorumAttested`!).
  * Specifically, post-`BRIDGE_V2_ACTIVATION_HEIGHT`:
    1. If `fraud_proven` (verified quorum retraction over `deposit_failure_signing_message_v2(chain_id, ...)` at `attestation_height`): **Path 2 — REVOKE** (challenger receives `bond + reward`, `amount - reward` burns out of escrow, `note_revoke(burn)`).
    2. Else if `confirmed_by_evidence` (verified `DepositProof` under V2 header+finality+PQ-height rules, or `QuorumAttested`): **Path 1 — CONFIRM** (clawback + bond slashed to recipient).
    3. Else if `now >= dispute.deadline`: **Path 3 — DEFER** (bounded) then fail-closed refuse (`SEC-01` preserved: unverifiable evidence never revokes).

---

## 3. Committed Height-Indexed PQ Keys (`PqRegistry` instead of `PQ_VALIDATOR_KEYS`)

### 3.1 Removing `get_validator_pq_key` from `bridge.rs:618`

`bridge.rs:618` currently calls `crate::consensus::get_validator_pq_key(id)`, reading the process-local static `PQ_VALIDATOR_KEYS` (`consensus/rotation.rs:8-10, 109-112`). That breaks determinism across nodes with differing `STELL_PEER_PQ_KEYS` and ignores PQ key rotation history.

Define a pure, consensus-deterministic lookup trait in `stellereum/src/bridge.rs` (zero global locks, zero env reads):

```rust
pub trait PqKeyLookup {
    /// Resolve the authoritative PQ key for `validator` AT committed `height`.
    /// Returns `None` fail-closed if unknown, pre-activation, or pruned.
    fn pq_key_at(
        &self,
        validator: &[u8; 32],
        height: u64,
    ) -> Option<(crate::post_quantum::PqScheme, Vec<u8>)>;
}

impl PqKeyLookup for crate::pq_registry::PqRegistry {
    fn pq_key_at(&self, validator: &[u8; 32], height: u64) -> Option<(PqScheme, Vec<u8>)> {
        self.get_active_key(validator, height)
    }
}

impl PqKeyLookup for (&crate::staking::StakingLedger, &crate::pq_registry::PqRegistry) {
    fn pq_key_at(&self, validator: &[u8; 32], height: u64) -> Option<(PqScheme, Vec<u8>)> {
        self.0.pq_active_key(self.1, validator, height)
    }
}
```

### 3.2 Threading Committed State & `attestation_height`

1. **`distinct_falcon_signers_at_height` & `verify_quorum_signatures_at_height` (`bridge.rs:574-633`):**
   * Signature: `verify_quorum_signatures_at_height(msg: &[u8], sigs: &[([u8; 32], Vec<u8>)], validators: &[[u8; 32]], attestation_height: u64, pq_keys: &dyn PqKeyLookup) -> Result<usize, String>`.
   * For every `(id, sig)` in `sigs`:
     * Deduplicate by `id` (`BTreeSet`), fail closed on `validators.is_empty()` or `!allowed.contains(id)`.
     * Resolve `pq_keys.pq_key_at(id, attestation_height)`: `None` -> `Err("bridge quorum: no committed PQ key at attestation height refused fail-closed")`.
     * Require `scheme == PqScheme::Falcon512` and `crate::consensus::verify_falcon_signature(&pk, msg, sig)` (no Ed25519 fallback).
2. **`state_engine` -> `BridgeState::plan_at_height` wiring (`apply.rs`, `parallel.rs`, `settlement.rs`):**
   * Thread `block_height: u64` from `apply_block_parallel_fees_with_events_at_height(..., chain_height)` (`parallel.rs:691`, called with `block.height` at `apply.rs:2704`) into `execute_payload_with_preverify_at_height(..., timestamp, height)` -> `settle_bridge_native(..., chain_id, height, pq_keys)`.
   * Inside `execute_payload_with_preverify_at_height`, read committed `staking = self.staking_read().await` and committed `pq_reg = self.pq_registry_read().await` (from `InMemoryStateEngine::pq_registry`, `07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md §2.3`), and pass `(&*staking, &*pq_reg)` as `&dyn PqKeyLookup`!
   * **Pre-activation (`height < BRIDGE_V2_ACTIVATION_HEIGHT`) only:** if a pre-W3 ledger has not yet migrated into `pq_registry`, `LegacyPreV2KeyLookup` may consult `staking.validator_pq_keys` (and pre-W3 tests via `consensus::pq_key_at_height`) ONLY while `height < BRIDGE_V2_ACTIVATION_HEIGHT`. At `height >= BRIDGE_V2_ACTIVATION_HEIGHT`, ONLY committed `PqRegistry` (via `(&staking, &pq_registry)`) is consulted; `get_validator_pq_key` is **completely removed** from `bridge.rs` and `bridge_adapters.rs`.
3. **`attestation_height` bounds & rotation `H-1 / H / H+1` semantics:**
   * For `ReleaseProof`, `attestation_height` is carried explicitly in `ReleaseReceiptEvidence` and must satisfy `attestation_height <= block_height` AND `block_height.saturating_sub(attestation_height) <= MAX_BRIDGE_ATTESTATION_AGE_HEIGHTS`.
   * For `DepositEvidence` (`TonCell`, `EvmReceipt`, `SolanaTx`, `QuorumAttested`), `Attest`, and `Resolve` retractions: add `attestation_height` on V2 evidence/attestation or bind `attestation_height = block_height` when no historical height field is present (with `AttestV2` / `DepositEvidence` optional V2 height field or `block_height` evaluation — if `attestation_height` is carried inside `QuorumAttestedV2` / header `attestation_height`, enforce the same `[block_height - MAX_BRIDGE_ATTESTATION_AGE_HEIGHTS, block_height]` bound).
   * At rotation effective height `E`:
     * Signatures at `attestation_height = E - 1` verify ONLY under the old key (`activated_at <= E - 1 < superseded_at`), and FAIL under the new key.
     * Signatures at `attestation_height = E` and `E + 1` verify ONLY under the new key (`>= E`), and FAIL under the old key.
     * Signatures with `attestation_height > block_height` or older than `PQ_EVIDENCE_RETENTION_HEIGHTS` (pruned) FAIL closed.

---

## 4. Disjoint File-Ownership Matrix, Fix Order & Mandatory Gate (`AGENTS.md §2, §4, §7, §8`)

### 4.1 Prerequisite & Coordination with W3 (`07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md`)

* **Prerequisite (`BF-0`):** Committed `PqRegistry` on `InMemoryStateEngine` (`07_PQ_VALIDATOR_LIFECYCLE_DRAFT.md §2.3`: `pq_registry.rs`, `staking.rs`, `commitment.rs`, `storage.rs`, `state_engine/mod.rs`). If `BRIDGE-FIX-FULL` executes before full W3 remote-signer (`W3-A2`/`W3-C3`), land the committed `InMemoryStateEngine::pq_registry` field + `"pq_registry"` sled tree + `Domain::PqRegistry` commitment first so `settle_bridge_native` reads a genuine committed `PqRegistry` without touching `consensus::PQ_VALIDATOR_KEYS`.
* **Shared-file coordination:** `protocol.rs` and `chain_spec.rs` are touched by both W3 (`A1`) and `BRIDGE-FIX-FULL` (`BF-2a`). Execute `BF-2a` sequentially after W3-A1 merges (or combine both into a single Ruleset/FORK_ID commit) — never let two active workers edit the same file simultaneously.

### 4.2 Strictly Disjoint Worker Matrix & Execution Order

| Echelon | Worker | Owned Files (Strictly Disjoint) | Scope & Exact Fixes | Prerequisite |
|---|---|---|---|---|
| **BF-0** | `W3-A1/B1/B2` (Prereq) | `stellereum/src/{pq_registry,staking,storage}.rs`, `stellereum/src/state_engine/mod.rs` | Committed `PqRegistry` on `InMemoryStateEngine` (`pq_registry_read/write`, `"pq_registry"` sled tree, `pq_active_key`). | Existing W3 spec §2.3 |
| **BF-1** | `BF-1b` (`bridge.rs`) | `stellereum/src/bridge.rs` | `BRIDGE_V2_ACTIVATION_HEIGHT` + test override; `PqKeyLookup` trait (remove `get_validator_pq_key` at `:618`); `BridgeIntent::ReleaseProof` (discriminant `8`); `ReleaseReceiptEvidence` + `BRIDGE_RELEASE_RECEIPT_DOMAIN_V2`; `BridgeState` extensions + `BridgeStateV3`; `plan_at_height` (reject bare `Release`, verify `ReleaseProof`, `Refund` tombstone, `Challenge` on `DepositProof` at `:1461,:1513`, `RETRACTION` precedence in `Resolve`); `Attest` cap `<= 1024`; bind `TonMultisigReleaseOrder` / `EvmReleaseOrder` / `MultisigRelayer` to `req_id`, `chain_id`, `PAYOUT_SAFETY_MARGIN_SECS`, `PqKeyLookup`. | `BF-0` |
| **BF-1** | `BF-1a` (`bridge_adapters.rs`) | `stellereum/src/bridge_adapters.rs` | `AdapterKindTag`; `StoredHeader::signing_message_v2`; `check_header_at_height` enforcing V2 (`chain_id`, `adapter_kind`, `finalized_head`) at `>= BRIDGE_V2_ACTIVATION_HEIGHT` (rejecting V1); strict chain/adapter pinning (`EvmAdapter` non-EVM refusal); `verify_evidence_at_height` & `verify_quorum_retraction_at_height` using `&dyn PqKeyLookup`. *(Run after `BF-1b` freezes `PqKeyLookup` & `verify_quorum_signatures_at_height`, or split interface freeze first.)* | `BF-1b` interface |
| **BF-2** | `BF-2a` (`Commitment & Protocol`) | `stellereum/src/commitment.rs`, `stellereum/src/protocol.rs`, `stellereum/src/chain_spec.rs` | Update `bridge_digest` (`commitment.rs:1497`) with `release_receipts`, `processed_payout_txs`, `refunded_withdrawals` (conditional: 0B when empty); register `BRIDGE_V2_ACTIVATION_HEIGHT` in `chain_spec.rs`; bump `CONSENSUS_RULESET_VERSION` & `DOMAIN_SET_VERSION` and fold `BRIDGE_V2_ACTIVATION_HEIGHT` + V2 domain strings into `FORK_ID_RULES` / `derive_fork_id` (`protocol.rs`). | `BF-1` |
| **BF-2** | `BF-2b` (`State Engine`) | `stellereum/src/state_engine/{apply,settlement,accounts,parallel}.rs` | Thread `(block_height, chain_id)` into `execute_payload_with_preverify_at_height` -> `settle_bridge_native` -> `BridgeState::plan_at_height`; pass committed `(&*staking, &*pq_registry)` as `&dyn PqKeyLookup`; add `BridgeStateV3` fallback in `accounts.rs::restore_bridge`. | `BF-1` (parallel with `BF-2a`) |
| **BF-2** | `BF-2c` (`VM, RPC, CLI`) | `stellereum/src/svm.rs`, `stellereum/src/native_api.rs`, `stellereum/src/cli/{args,tx_builders}.rs` | Confirm `SysCallBridge(ReleaseProof)` gas & `validate()` in `svm.rs:2843`; expose `release_receipt` / `refunded` in `stell_bridgeStatus` & `stell_bridgeReleaseEstimate` (`native_api.rs:1622-1881`); add `ReleaseProof` CLI builder/args without altering legacy `Deposit`/`Withdraw`/`Refund` builders. | `BF-1` (parallel with `BF-2a/2b`) |
| **BF-3** | `BF-3a` (`Examples & Bin Tests`) | `stellereum/examples/vuln_hunt5.rs`, `stellereum/src/bin_tests.rs` | **Fix `examples/vuln_hunt5.rs:690-702` (`bridge_release` `#38` & `#39`):** replace raw Ed25519 signing over raw `msg` with `FalconKeypair` signing `MultisigRelayer::release_signing_message([2u8; 32], msg)` (and `[3u8; 32]`) against a deterministic `PqRegistry` / `PqKeyLookup` fixture (no global `PQ_VALIDATOR_KEYS`, no Ed25519). Update `bin_tests.rs:1599` for `plan_at_height` if needed. | `BF-2` |
| **BF-3** | `BF-3b` (`Bridge & Regression Tests`) | `stellereum/tests/{bridge_authorization_p0_regression,bridge_adapters_tests,bridge_dispute_tests,bridge_onchain_tests,bridge_persistence_tests,bridge_oracle_audit_tests,multisig_model_op_binding_regression,audit_closure_bridge_tests}.rs` | Verify all 4 tests in `bridge_authorization_p0_regression.rs` pass unchanged; update `bridge_dispute_tests::challenge_evidence_path_deposit_is_refused` (`:709`) for post-v2 challengeability (keeping pre-v2 `H-1` check); update bare-`Release` fixtures in `bridge_onchain_tests.rs:473`, `bridge_persistence_tests.rs:573`, and `audit_closure_bridge_tests.rs:1231` to pair `ReleaseProof` post-v2; add `H-1 / H / H+1`, adapter-mixing, PQ-rotation-height, and `BridgeStateV3` tests; run full gate. | `BF-2` (parallel with `BF-3a`) |

### 4.3 Specific Contract for `stellereum/examples/vuln_hunt5.rs:690-702`

Currently (`stellereum/examples/vuln_hunt5.rs:690-702`):
```rust
    // #38: a lone validator still has to actually sign.
    let k = SigningKey::generate(&mut OsRng);
    let mut one = MultisigRelayer::new(vec![k.verifying_key().to_bytes()]);
    let msg = b"release 100 STELL";
    let sig = (
        k.verifying_key().to_bytes(),
        ed25519_dalek::Signer::sign(&k, msg).to_bytes().to_vec(),
    );
    r.check(
        "#38 lone validator must sign",
        one.try_release([2u8; 32], msg, &[]).is_err()
            && one.try_release([2u8; 32], msg, &[sig]).is_ok(),
        "unsigned refused, signed accepted",
    );
```
This is broken on two invariants already enforced in `bridge.rs`:
1. `MultisigRelayer::count_signers` (`bridge.rs:1944-1947`) verifies **Falcon-512** signatures against a committed PQ key, NOT Ed25519 (`64B` signatures fail closed).
2. `MultisigRelayer::try_release` (`bridge.rs:1964-1984`) requires signatures over `MultisigRelayer::release_signing_message(op_id, msg)` (`b"STELLEREUM_MULTISIG_RELAYER_MODEL_RELEASE_V1" || op_id || msg`), NOT raw `msg`.

**Required fix in `BF-3a` (`vuln_hunt5.rs:671-718`):**
* Generate a deterministic or fresh `FalconKeypair` paired with validator id `id = k.verifying_key().to_bytes()`, register `(id, PqScheme::Falcon512, fk.public_key)` into the explicit `PqRegistry` / `PqKeyLookup` passed to `MultisigRelayer` (never relying on `PQ_VALIDATOR_KEYS`), and sign `MultisigRelayer::release_signing_message([2u8; 32], msg)` with `fk.sign(...)` for `#38` (and `[3u8; 32]` with `outsider_fk` for `#39`), while also asserting that a raw `ed25519_dalek` signature and a signature over raw `msg` (without `release_signing_message`) are both rejected.

### 4.4 Mandatory Verification & Frozen-Core Gate (`AGENTS.md §4, §7`)

`BRIDGE-FIX-FULL` is NOT complete until every item below passes and command outputs are recorded:
1. **P0 Regressions (`bridge_authorization_p0_regression.rs`):**
   * `outsider_release_cannot_destroy_the_senders_refund_path` passes unmodified (bare `Release` rejected at/after `unlock_at`; sender `Refund` succeeds at `refund_at`).
   * `ton_unsigned_finalized_seqno_cannot_promote_a_shallow_proof`, `evm_unsigned_finalized_number_cannot_promote_a_shallow_proof`, `solana_unsigned_finalized_slot_cannot_promote_a_shallow_proof` all pass unmodified.
2. **Activation & Boundary Matrix (`H - 1 / H / H + 1`):**
   * `H - 1`: V1 header, bare `Release`, and legacy pre-v2 evidence-path challenge exclusion replay cleanly.
   * `H` & `H + 1`: V1 header rejected; cross-adapter (`TonCell` sigs on `EvmReceipt`, `Arbitrum` on `Ethereum`) rejected; cross-`chain_id` rejected; bare `Release` (by outsider OR sender) rejected; `Release + ReleaseProof` with wrong `req_id` / `amount` / `target_address` / replayed `external_tx_hash` / sub-quorum / stale rotated key rejected; valid `Release + ReleaseProof` commits `ReleaseReceiptRecord`, blocks subsequent `Refund`, and rejects duplicate `external_tx_hash` on a second withdrawal.
   * Challenge on `DepositProof` (`QuorumAttested`, `TonCell`, `EvmReceipt`, `SolanaTx`) succeeds post-`H`, and `Resolve` with quorum retraction revokes and burns even when the original quorum-signed `DepositProof` is replayed.
   * PQ key rotation boundary at `E - 1 / E / E + 1`: old key valid at `E - 1` and rejected at `E`; new key rejected at `E - 1` and valid at `E`; pruned/future `attestation_height` rejected fail-closed; `get_validator_pq_key` absent from `bridge.rs` / `bridge_adapters.rs`.
3. **Full Frozen-Core Gate:**
   * `cargo clippy --all-targets -- -D warnings` (must include `--examples`, catching `vuln_hunt5.rs`) -> 0 warnings, 0 errors.
   * `cargo test --no-fail-fast` on all bridge, adapter, state-engine, commitment, and example targets -> green.
   * `consensus_liveness_harness` and `./scripts/verify_testnet_ideal.sh` -> green.
