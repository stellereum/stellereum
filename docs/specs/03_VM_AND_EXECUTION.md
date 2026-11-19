# 03 — VM & Execution (HDAE canonical, 2026-10-29)

Source of truth: `stellereum/src/contract.rs`, `contract_abi.rs`,
`contract_source.rs`, `state_engine.rs`, `evm_adapter.rs`, `simulator.rs`.

## Execution model

- WASM engine: `wasmi` 2.0 (`std, validate, deterministic, portable-dispatch`).
- **13 host functions** (pinned set; additions need ABI version bump).
- Canonical contract source form is **`.wat` text** (`contracts/*.wat`);
  `stell_verifyContractSource` recompiles with the `wat` crate and compares.
- EVM adapter exists (`evm_adapter/`) for compatibility flows; gas fields
  mirror EVM (EIP-1559 supported) but there is **no EVM interpreter or EVM
  state trie**. The write path is FULL-PQ: `SysCallBindEvmAddress` records an
  `EVM address → PQ account` binding (Falcon statement), then
  `SysCallEvmCarrier` settles a value transfer (empty calldata, value > 0)
  under a second Falcon signature over `keccak256(evm_tx)`; contract creation
  and calldata are refused. The binding index is node-local routing, not in
  the state root; consensus re-verifies the signatures from block bytes.
- Deterministic builds: `simulator.rs` + `InMemoryStateEngine` give
  byte-identical results for identical inputs (differential-tested).

## Account model

- Account Object = on-chain program-passport (owner/guardian/renter/sessions,
  ceiling only ratchets down, tombstone, guardian delay 72h). Siloed Vault is
  by-convention, not consensus-enforced.
- Native APIs: 22 pinned (`stell_nativeApi` surface). Faucet, estimateFee,
  archive proofs, epoch keys, contract source registry included.

## Mempool rules (consensus-critical, do not relax)

1. Priority ordering by fee; per-sender nonce window enforced.
2. Shard pinning: txs route by `tx_belongs_to_shard`; cross-shard gated.
3. Activation buffer: cross-shard value uses the §9 2PC from genesis
   (`XPC_ACTIVATION_HEIGHT = 0`, compiled; `STELL_XPC_ACTIVATION_HEIGHT` is
   deprecated and ignored). Legacy records from a pre-2PC chain keep their
   outbox/inbox/ack/bounce lifecycle.
4. Failure-fee: failed apply still charges (anti-spam invariant).

## State & proofs

- Compressed Patricia Trie (`cpat2.rs`) with exclusion proofs
  (pinned by `test_exclusion_proof_*`).
- MMR epoch roots committed in blocks (epoch length 128,
  `stell_getEpochRoot`).
- Archive proofs + historical roots via `stell_getArchiveProof`.
