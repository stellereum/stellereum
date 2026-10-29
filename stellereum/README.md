> **⚠️ Unaudited testnet — do not use real funds.** Internal audits and penetration tests are done (see [`docs/audits/`](docs/audits/)), but no independent external audit has completed yet. Published for testnet use and review only.

# Stellereum Network (STELL)

<p align="center">
  <a href="https://github.com/immtes/stellereum/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/immtes/stellereum/ci.yml?label=CI" alt="CI"/></a>
  <img src="https://img.shields.io/badge/tests-936%20passing%20%28cargo%20test%20--lib%29-brightgreen" alt="lib tests, measured 2026-10-25"/>
  <img src="https://img.shields.io/badge/fuzz-7%20decode%20harnesses-blue" alt="fuzz targets"/>
  <img src="https://img.shields.io/badge/testnet-local--only%20%28public%20RPC%20502%20on%202026--10--25%29-yellow" alt="testnet status"/>
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-orange" alt="License"/></a>
  <a href="docs/RPC.md"><img src="https://img.shields.io/badge/docs-RPC%20%7C%20ops%20%7C%20sharding-lightgrey" alt="Docs"/></a>
</p>

> **Badge freshness (no stale numbers):** `970` = `cargo test --lib` → `970 passed; 0 failed` on 2026-10-25 (re-run to refresh; the tree moves fast — it read 936 earlier the same day). `7` = `ls fuzz/fuzz_targets/*.rs`. Public RPC `https://rpc.stellereum.org` returned HTTP 502 on 2026-10-25, so there is no live tip to link — run the local stack below instead. Public RPC `https://rpc.stellereum.org` returned HTTP 502 on 2026-10-25, so there is no live tip to link — run the local stack below instead.

**Pitch.** Stellereum is an in-development Rust L1 for high-frequency trading and AI agents: TON-style actor accounts and BoC state, a masterchain plus auto-splitting workchain shards, BFT finality with post-quantum validator keys, a native on-chain order book, and private transfers — all runnable on lightweight hardware. Stage: fully working local simulator and deterministic devnet, multi-node testnet configs shipped, no production network and no external audit yet. `chainId 5757`; testnet only.

```text
                    ┌─────────────────────────────────────────┐
                    │              MASTERCHAIN (shard 0)      │
                    │ validator set · shard headers (SHARDHDR)│
                    │ order-root + epoch-key block commitments│
                    └───────┬─────────────────────────┬───────┘
                            │ prefix routing          │
            ┌───────────────▼────────┐ ┌──────────────▼─────────┐
            │ WORKCHAIN SHARD 1      │ │ WORKCHAIN SHARD 2 … ≤16│
            │ actor accounts · BoC   │ │ split ≥500 / merge ≤50 │
            │ CLOB order book · SVM  │ │ address space 2^60     │
            └────────────────────────┘ └────────────────────────┘
   ┌──────┐  ┌──────────┐  ┌───────────────────────────────────┐
   │  PQ  │  │ MEMPOOL  │  │  BFT: sortition-seeded µQC, quorum │
   │ keys │─▶│ sealed   │─▶│  floor(2P/3)+1 incl. network-majority│
   └──────┘  └──────────┘  └───────────────────────────────────┘
   ┌────────────────────────────────────────────────────────────┐
   │ JSON-RPC/WS :8545 (stell_*) · explorer gateway :8080      │
   │ indexer (../stellereum-indexer/) · explorer (../explorer-site/) │
   └────────────────────────────────────────────────────────────┘
```

## Quickstart — first signed transaction in 5 commands

```bash
git clone https://github.com/immtes/stellereum.git && cd stellereum
cargo build                                   # 1. build the node
./target/debug/stellereum wallet generate     # 2. fresh keypair + stealth address
./target/debug/stellereum wallet address --from-key <PRIVATE_KEY>  # 3. re-derive address
# 4. sign a transfer OFFLINE (no node needed; --nonce skips the RPC lookup)
./target/debug/stellereum wallet send --from-key <PRIVATE_KEY> --to <ADDR> --amount 1000000000 --nonce 0 --dry-run
./target/debug/stellereum sim --blocks 3      # 5. full stack: BFT + shards + CLOB + zkML + bridge
```

(All five verified against this tree on 2026-10-25; `send` without `--dry-run` submits to `--rpc http://127.0.0.1:8545`.) Next: [`testnet/README.md`](testnet/README.md) for a real multi-node stand, [`docs/VALIDATOR_ONBOARDING.md`](docs/VALIDATOR_ONBOARDING.md) to validate.

## Repo map

| Path | What lives there |
| :--- | :--- |
| `src/` | node: consensus, mempool, shards, PQ crypto, RPC, wallet, bridge, SVM/CLOB |
| `tests/` / `benches/` | integration suites / release-profile benches (`packing`, `svm_hot_path`, …) |
| `fuzz/fuzz_targets/` | 7 `*_decode` harnesses; generated corpus under `fuzz/corpus/` is git-ignored |
| `docs/` | `PROTOCOL.md` (consensus rules), `RPC.md`, `OPERATIONS.md`, `SHARDING.md`, `PERF_1K.md`, `audits/` |
| `testnet/` | 2-node configs, `genesis.env`, stand guide |
| `contracts/` `examples/` `scripts/` `site/` | STS-20/token contracts, demos, ops scripts, static site |
| `../explorer-site/` `../stellereum-indexer/` `../stell-wallet/` | explorer+ faucet, indexer, wallet (sibling dirs, own READMEs) |
| `../stellereum-sdk/` | canonical tx-builder SDK (B2 closer): 5 builders, bound-by-default envelopes, [`SDK-README.md`](../stellereum-sdk/SDK-README.md) |

## Performance — measured only, bench vs live labeled

| Figure | Value | How obtained (re-run it) |
| :--- | :--- | :--- |
| Lib tests | **970 passed, 0 failed** | `cargo test --lib`, 2026-10-25, debug |
| Block apply, mixed 428 tx | **8.45 ms wall (~50k tx/s in-process)** | BENCH, release, Ryzen 5 3600 (`benches/packing.rs`, via [`docs/PERF_1K.md`](docs/PERF_1K.md)) |
| Mempool select, pool 428/1k/10k | **35.0 / 60.2 / 550.5 µs** | BENCH, same host/profile |
| Simulator block finality | **~1.7 ms** | in-process `sim`, NOT network (sample in old docs) |
| Live stand block time | **seconds per block** (transport-bound) | live observation, NOT a bench — `<120 ms` remains a target |
| Throughput math | 1785 tx/block ÷ 0.4 s floor ≈ 4462 TPS | DERIVED from the 500M gas cap, not measured end-to-end |

## Security

Internal program completed: protocol, consensus, mempool/P2P, PQ crypto, staking/economics, storage/sync, bridge/privacy, RPC/EVM pentests — full package in [`docs/audits/`](docs/audits/) (`INVARIANTS.md`, `THREAT_MODEL.md`, `KNOWN_ISSUES.md`, `EXTERNAL_AUDIT_BRIEF.md`). Chain-id binding (`STELLEREUM_BLOCK_V3`, default id 5757), order-root and shard-header commitments are consensus-enforced; large bridge withdrawals park behind a 1 h timelock with a 2/3-distinct-validator quorum. **External audit: pending — the brief is ready, the audit is not.** Report issues via [`SECURITY.md`](../SECURITY.md); never open a public issue for a suspected vulnerability.

## Contributing · License · Links

No formal contributing process yet — open an issue with a reproducer (`sim`/`devnet` seed included) before large PRs; keep `cargo test --lib` green and refresh the badge numbers above when they move. License: MIT **or** Apache-2.0 ([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)). Entry docs: [`PROTOCOL.md`](PROTOCOL.md) · [`docs/OPERATIONS.md`](docs/OPERATIONS.md) · [`docs/RPC.md`](docs/RPC.md) · [`docs/SHARDING.md`](docs/SHARDING.md) · [`docs/PERF_1K.md`](docs/PERF_1K.md) · [`testnet/README.md`](testnet/README.md) · [`../explorer-site/README.md`](../explorer-site/README.md).
