# RULESET V7 — unified activation of R1..R4 hardening, light-client commitment, PQ lifecycle, bridge V2 & W4 economics

Ruleset 7 is a coordinated consensus hard fork activating all 8 Ruleset v7 feature
gates at height `0` (clean v7 genesis). All wire domains, header/body
commitments, activation heights, and evidence-retention bounds are folded into
`FORK_ID`, so mixed v6/v7 fleets fail closed at handshake.

| Field | Value |
|---|---|
| `PROTOCOL_VERSION` | 1.0 (unchanged) |
| `CONSENSUS_RULESET_VERSION` | **7** (bumped from `6`) |
| `DOMAIN_SET_VERSION` | **4** (bumped from `3`) |
| `FORK_ID` | **`0x3ae00ebc`** (was `0x0f584a46`) |
| Rules folded into `FORK_ID_RULES` | **32** (`23` v6 rules + `9` v7 rules) |
| Domains folded into `derive_fork_id` | **16** (`7` v6 domains + `9` v7 domains) |
| `MAX_BLOCK_TIMESTAMP_DRIFT_MS` | `3_600_000` (1 hour, unchanged) |
| Genesis | new (a v6 data directory is refused by fork_id / commitment rules) |

## Activated Gates (all `0` = `ActiveFromGenesis`)

1. **`EXEC_HARDENING_V1_ACTIVATION_HEIGHT = 0`** (`stellereum/src/chain_spec.rs`):
   `OpCode::Halt` scan barriers across block scanners (`bridge_intents`,
   `rotation_aliases`, `apply_cnvrf_v3`, `apply_staking_unjail_ops`,
   `apply_equivocation_slash`), `SysCallCallContractArgs` /
   `SysCallSubmitPqPriceFeed` rollback snapshots, `TX_INTRINSIC_GAS = 280_000`
   minimum billing floor, and CLOB `MAX_MATCH_FILLS_PER_ORDER = 256` +
   read-only `CancelOrder` pre-check.
2. **`WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT = 0`** (`stellereum/src/chain_spec.rs`):
   `SubCallSnapshot` atomic sub-call rollback, `caller()` vs `origin()`,
   `validate_code_hardened` fuel, per-byte `send_message` fuel,
   `deploy_with_nonce(tx.nonce)`, post-`commit_native` `outbound_messages` +
   `sync_contract_balance` + bounce conservation, PMM `wUSDT` CEI +
   `ZeroMint`/`ZeroPayout`, `cross_shard_completed` guard, and canonical `PQ1`
   envelope decoding (`decode_canonical`).
3. **`HEADER_COMMIT_ACTIVATION_HEIGHT = 0`** (`stellereum/src/sharding/block.rs`):
   Two-level `BlockHeader` v4 (`STELLEREUM_BODY_V4\0` + `STELLEREUM_HDR_V4\0`)
   binding `state_root` and `prev_hash` into `block_hash`, plus fail-closed
   light-client / CLI / sync header-hash verification.
4. **`EVM_BINDINGS_STATE_ACTIVATION_HEIGHT = 0`** (`stellereum/src/state_engine/mod.rs`):
   Canonical `Domain::EvmBindings` state commitment and deterministic
   first-writer-wins apply + `SnapV4` unit `271`.
5. **`PQ_LIFECYCLE_ACTIVATION_HEIGHT = 0`** (`stellereum/src/pq_registry.rs`):
   3-key validator separation (`ValidatorId` / `voting_pubkey` / cold
   `withdrawal_address`), Falcon-512 PoP (`STELL_PQ_KEY_POP_V1`) +
   `STELL_VAL_ID_V1`, `next_seq` replay guard, explicit `cancel_rotation`,
   720,000-height (`PQ_EVIDENCE_RETENTION_HEIGHTS`) evidence retention with
   32-entry hard cap, `OpCode 59..=64`, `Domain::PqRegistry`, and `RemotePqSigner`
   v2 without local fallback.
6. **`BRIDGE_V2_ACTIVATION_HEIGHT = 0`** (`stellereum/src/bridge.rs`):
   Mandatory `BridgeIntent::ReleaseProof` (discriminant `8`,
   `STELL_BRIDGE_RELEASE_RECEIPT_V2`), `processed_payout_txs` replay guard,
   `refunded_withdrawals` tombstone, `BridgeStateV3`, `StoredHeader` V2
   (`STELL_BRIDGE_HEADER_V2` binding `chain_id`, `AdapterKindTag`, and
   `finalized_head`), strict EVM pinning, challengeable `DepositProof`,
   `RETRACTION` precedence in `Resolve`, and committed height-indexed
   `PqKeyLookup`.
7. **`FEE_MARKET_V2_ACTIVATION_HEIGHT = 0`** (`stellereum/src/tokenomics.rs`):
   `priority_fee_per_gas` charged in sequential/parallel/payload apply and exact
   block-level `u128` split (`50%` burn, `30%` proposer, `20%` staking pool via
   `distribute_fee_reward`, conserving `1B` supply cap and `350M` emission cap).
8. **`SUB_NANO_STRICT_ACTIVATION_HEIGHT = 0`** (`stellereum/src/tokenomics.rs`):
   Exact `wei_to_nano_exact` on EVM carrier boundaries, `ValidatorRewardState`
   carry rescaling on `delegated` changes (`accrue_with_rescale`), single-step
   256-bit `GenesisVault::calculate_mint`, integer `eth_feeHistory`, and
   committed `StakingLedger::emission_carry_q64` (`STAKING_EMISSION_CARRY_V1`).

## New `FORK_ID_RULES` & Domains (`protocol.rs`)

- Appended rules (`23..32`): `EXEC_HARDENING_V1_ACTIVATION_HEIGHT`,
  `WASM_XSHARD_PMM_HARDENING_ACTIVATION_HEIGHT`,
  `HEADER_COMMIT_ACTIVATION_HEIGHT`, `EVM_BINDINGS_STATE_ACTIVATION_HEIGHT`,
  `PQ_LIFECYCLE_ACTIVATION_HEIGHT`, `PQ_EVIDENCE_RETENTION_HEIGHTS` (`720_000`),
  `BRIDGE_V2_ACTIVATION_HEIGHT`, `FEE_MARKET_V2_ACTIVATION_HEIGHT`,
  `SUB_NANO_STRICT_ACTIVATION_HEIGHT`.
- Appended domains: `STELLEREUM_BODY_V4\0`, `STELLEREUM_HDR_V4\0`,
  `STELL_PQ_KEY_POP_V1`, `STELL_VAL_ID_V1`, `STELL_BRIDGE_RELEASE_RECEIPT_V2`,
  `STELL_BRIDGE_HEADER_V2`, `TON_MULTISIG_RELEASE_V2`,
  `EVM_TELEPORT_RELEASE_V2`, `STELLEREUM_MULTISIG_RELAYER_MODEL_RELEASE_V2`.

## Upgrade Note

New genesis (`docs/FRESH_GENESIS_RUNBOOK.md`). Ruleset v6 (`0x0f584a46`) and v7
(`0x3ae00ebc`) peers refuse consensus handshake cleanly with
`NegotiationRefusal::ForkMismatch`.
