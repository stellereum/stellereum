# 01 — Architecture Overview (HDAE canonical, 2026-10-29)

> **Current consensus ruleset: v6** (`FORK_ID = 0x0f584a46`, 23 rules).
> v6 compares locks by round-free `Block::value_id` and re-stamps a rescued
> body at the proposer's current round; it is the activation marker for the
> live-stall fix (`docs/RULESET_V6.md`). Rulesets v2–v5 were the height
> re-scale, shard-bound vote preimage, signed block round + timestamp bound,
> and chain-wide supply cap (historical pages `docs/RULESET_V2.md`..`V5.md`).

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

- `stellereum/` is the ONLY canonical node tree (146 `.rs` files: 67
  top-level modules plus the `consensus/`, `runtime/`, `state_engine/`,
  `rpc/`, `sharding/` and `evm_adapter/` directories). The diverged stale
  copies `stellereum_head/` and `w8/` were REMOVED 2026-10-29 (recoverable
  from git history if archaeology is ever needed).
  See `CRATE_ISOLATION_PLAN.md`.
- Live topology: A `212.113.103.105`, B local `:8546`, C `77.110.96.68:2222`,
  D `138.124.102.200`. N=4, quorum 2f+1, set 4/4 non-fragile.

## Subsystem map (stellereum/src)

| Domain | Files | Frozen surface |
|---|---|---|
| Primitives/addressing | `address.rs`, `cell.rs`, `chain_binding.rs` | `Stl57` format (Base58 + BLAKE3 checksum), chain-id binding |
| Consensus/BFT | `consensus/`, `runtime/`, `node/`, `consensus_net.rs` | parent-hash sortition (V5 draw), µQC `min(N, 128)` seats, tick floor 50 ms, base timeout 3 000 ms (current ruleset v6) |
| Execution/VM | `contract.rs`, `contract_abi.rs`, `contract_source.rs`, `state_engine.rs`, `evm_adapter.rs` | wasmi, 13 host fns, canonical `.wat` source form |
| Storage/state | `cpat2.rs` (trie), `storage.rs`, `chain.rs`, `mmr.rs` | exclusion proofs, MMR epoch roots (epoch 500) |
| Economics | `staking.rs`, `token.rs`, `tokenomics.rs`, `clob*.rs`, `amm*.rs`, `perps*.rs`, `mev*.rs` | chain-wide `TOTAL_SUPPLY_CAP` (`SupplyPartition` + committed aggregate), F1 reward accumulator, failure-fee on apply-fail |
| Privacy | `silentpay.rs`, `wallet_signing.rs` | silent-payment prototype (`silentpay.rs`, UNWIRED); no confidential/shielded ledger — the Ristretto path was deleted; `STELL-MSGSIG-V1` wallet signing |
| Cross-shard/bridge | `xshard2pc.rs`, `bridge.rs`, `bridge_adapters.rs` | 2PC armed by compiled `XPC_ACTIVATION_HEIGHT = 0` (active from genesis), truth-gate bridge |
| Crypto | `post_quantum.rs`, `vrf.rs`, `cn_vrf.rs` | Falcon-512 vote/QC signatures (FIPS 206); no BLS/pairing path (deleted); parent-hash sortition, CN-VRF v3 implemented with its activation gate off |
| Interfaces | `rpc/`, `native_api.rs`, `light_client.rs`, `simulator.rs`, `mempool.rs` | 32-method native API catalog, mempool priority+shard-pin+nonce-window |

## Frozen core contracts (change = audit + spec update)

1. Wire format of blocks/votes/QCs (any byte change forks the chain).
2. Quorum values (2f+1, µQC `min(N, 128)`) and timeout constants' safety roles.
3. State-transition function (apply) — differential tests pin it.
4. Address format `Stl57`, chain-id binding, signature domains.
5. Snapshot/restore layout compatibility (resync depends on it).
