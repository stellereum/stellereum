# 01 — Architecture Overview (HDAE canonical, 2026-10-29)

> **Current consensus ruleset: v5** (`FORK_ID = 0x9d59096b`, 23 rules).
> Consensus-rule changes since this page was written: v2 height re-scale,
> v3 shard-bound vote preimage, v4 signed block round + timestamp bound,
> v5 chain-wide supply cap. See `docs/RULESET_V5.md` and `docs/SUPPLY_CAP.md`.

Supersedes: all `handoff/*` diaries and `docs/audits/audit-*.md` working notes
(full list in `.archive/README.md`). Canonical audit: root
`COMPREHENSIVE_AUDIT_REPORT.md` (PART I byte-frozen). Master protocol spec:
`handoff/STELLEREUM_PQ_BFT_V5_MASTER_SPEC.txt`.

## Workspaces (no root workspace; gates loop over all six)

| Workspace | Members | Role |
|---|---|---|
| `stellereum/` | `stellereum` (single package) + path dep `infnode` | Canonical node: consensus, execution, storage, RPC, P2P |
| `infnode/` | `infnode`, `infmail` | Overlay network (QUIC+DHT+storage) + webmail backend |
| `stellereum-contracts/` | `stellereum-sdk`, `e2e-tests`, `stl-dns`, `sts20-token`, `liquidity-pool`, `account-object` | On-chain contracts + contract SDK |
| `stellereum-indexer/` | single | SQLite indexer, `/api/v2/*` |
| `stellereum-sdk/` | single | Canonical client SDK (byte-pinned) |
| `stell-wallet/` | lib + bin | Wallet CLI + light client |
| `scripts/tools/stelops/` | single | Operator CLI (checkpoints, snapshots, divergence scan) |

## Canonical vs copies

- `stellereum/` is the ONLY canonical node tree (60 src files). The diverged
  stale copies `stellereum_head/` (48 files) and `w8/` (55 files) were REMOVED
  2026-10-29 (recoverable from git history if archaeology is ever needed).
  See `CRATE_ISOLATION_PLAN.md`.
- Live topology: A `212.113.103.105`, B local `:8546`, C `77.110.96.68:2222`,
  D `138.124.102.200`. N=4, quorum 2f+1, set 4/4 non-fragile.

## Subsystem map (stellereum/src)

| Domain | Files | Frozen surface |
|---|---|---|
| Primitives/addressing | `address.rs`, `cell.rs`, `chain_binding.rs` | `Stl57` format (Base58 + BLAKE3 checksum), chain-id binding |
| Consensus/BFT | `consensus/`, `runtime/`, `node/`, `consensus_net.rs` | V5 sortition (parent-hash), µQC `min(N, 128)` seats, tick floor 50 ms, base timeout 3 000 ms (ruleset v5) |
| Execution/VM | `contract.rs`, `contract_abi.rs`, `contract_source.rs`, `state_engine.rs`, `evm_adapter.rs` | wasmi, 13 host fns, canonical `.wat` source form |
| Storage/state | `cpat2.rs` (trie), `storage.rs`, `chain.rs`, `mmr.rs` | exclusion proofs, MMR epoch roots (epoch 500) |
| Economics | `staking.rs`, `token.rs`, `tokenomics.rs`, `clob*.rs`, `amm*.rs`, `perps*.rs`, `mev*.rs` | chain-wide `TOTAL_SUPPLY_CAP` (`SupplyPartition` + committed aggregate), F1 reward accumulator, failure-fee on apply-fail |
| Privacy | `crypto_privacy.rs`, `wallet_signing.rs` | shielded transfer/unshield, `STELL-MSGSIG-V1` |
| Cross-shard/bridge | `xshard2pc.rs`, `bridge.rs`, `bridge_adapters.rs` | 2PC armed by compiled `XPC_ACTIVATION_HEIGHT = 0` (active from genesis), truth-gate bridge |
| Crypto | `post_quantum.rs`, `bls.rs`, `vrf.rs` | Falcon FIPS-206, BLS12-381 (no PoP — structural), VRF planned |
| Interfaces | `rpc.rs`, `native_api.rs`, `light_client.rs`, `simulator.rs`, `mempool.rs` | 22 native APIs, mempool priority+shard-pin+nonce-window |

## Frozen core contracts (change = audit + spec update)

1. Wire format of blocks/votes/QCs (any byte change forks the chain).
2. Quorum values (2f+1, µQC `min(N, 128)`) and timeout constants' safety roles.
3. State-transition function (apply) — differential tests pin it.
4. Address format `Stl57`, chain-id binding, signature domains.
5. Snapshot/restore layout compatibility (resync depends on it).
