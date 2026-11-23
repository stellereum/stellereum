<p align="center">
  <img src="docs-site/public/logo.svg" width="132" alt="Stellereum logo"/>
</p>

<h1 align="center">Stellereum</h1>

<p align="center">
  <strong>Pure post-quantum Layer 1, written in Rust.</strong><br/>
  Falcon-512 votes and transactions · single-block BFT finality · workchain sharding ·
  WASM contracts · native CLOB/PMM.
</p>

<p align="center">
  <a href="stellereum/LICENSE"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License: MIT OR Apache-2.0"/></a>
  <a href="https://testnet.stellereum.org"><img src="https://img.shields.io/badge/status-public%20testnet-yellow" alt="Public testnet"/></a>
  <img src="https://img.shields.io/badge/language-Rust-000?logo=rust" alt="Rust"/>
  <a href="docs-site/security/status.md"><img src="https://img.shields.io/badge/external%20audit-none%20completed-critical" alt="No external audit completed"/></a>
</p>

> [!WARNING]
> **Testnet only — no independent external audit.** Stellereum is not mainnet.
> Testnet STELL has no value, state may be reset, and the code has not been
> attested by a third party. Do not deposit real funds, reuse production keys,
> or treat testnet uptime as a service-level commitment. See
> [Security status](docs-site/security/status.md).

Stellereum (STELL) is a post-quantum Layer 1 that keeps consensus, execution,
state and networking in one Rust node. There is no separate execution client, no
EVM interpreter, and no classical signature fallback for value.

## Why Stellereum

- **Post-quantum without a fallback lane.** Consensus votes and value-moving
  transactions are Falcon-512 inside a `PQ1` envelope; node transport uses
  ML-KEM-768. Ed25519 is not a signing lane; it survives at most as the 32-byte
  validator id.
- **Finality in one block.** BFT rounds run propose → prevote → precommit →
  commit. A precommit quorum of `floor(2 · power / 3) + 1` makes a block final;
  the live four-validator set needs three signatures, so one validator may be
  offline without stopping the chain.
- **Sharding with an honest scope.** Shard 0 (masterchain) is live. The fixed
  pair `{0,1}` is supported in one node process with two-phase commit; shard 1
  is parked on the public network, and every other shard set is experimental
  and off.
- **A market and a VM in the base layer.** `wasmi` contract execution with
  integer-only calls, a closed host interface (13 original functions plus
  `origin`), fuel charged before every effect, hard code/memory/storage caps, a
  native CLOB and PMM, account objects, and scoped session keys — all without an
  external DeFi stack.

## Status

| Property | Value |
| --- | --- |
| Network | **Public testnet** (no mainnet) |
| Native token | **STELL**, 9 decimals (1 STELL = 10⁹ nano-STELL) |
| Chain ID | **5757** (`0x167d`) |
| Consensus ruleset | **v7** |
| Fork ID | **`0x3ae00ebc`** |
| Shard state | Shard 0 live; fixed `{0,1}` pair supported in one process; shard 1 parked; other sets experimental/off |
| Block tempo | Live fleet sets `STELL_MIN_BLOCK_MS=400`; the compiled default is 50 ms and the value is local production policy, not a consensus rule |
| Finality | Single block; quorum `floor(2 · power / 3) + 1` |
| Signatures | Falcon-512 only (`PQ1` envelope); no classical transaction or vote lane |
| Transport | ML-KEM-768 encapsulation keys; Falcon-512 peer identity |
| Audit status | **No independent external audit completed**; internal review, fuzz and pentest batteries only |
| Faucet policy | 2 STELL per drip; 45-minute cooldown per address; 20 requests/hour/IP; 50 STELL lifetime cap per address |

Ruleset v7 changes the fork id and requires a v7 genesis. A node reporting a
different fork id is not on this network and is refused at the consensus
handshake.

## Repository map

| Path | Purpose | Documentation |
| --- | --- | --- |
| `stellereum/` | Node binary: BFT consensus, execution, state, storage, RPC, mempool, PQ crypto, CLI | [crate README](stellereum/README.md) · [architecture](docs-site/get-started/architecture.md) |
| `infnode/` | QUIC + DHT transport: PQ peer identity, discovery, pubsub, bounded storage | [crate README](infnode/README.md) |
| `stellereum-indexer/` | Chain indexer and REST API over SQLite WAL | [README](stellereum-indexer/README.md) · [indexer API](docs-site/api/indexer-rest.md) |
| `stellereum-sdk/` | Canonical Rust transaction-builder and signing SDK | [README](stellereum-sdk/README.md) · [SDK guide](docs/SDK.md) |
| `sdk-js/` | TypeScript client and EIP-1193-style read provider | [README](sdk-js/README.md) · [TypeScript SDK](docs-site/sdk/typescript.md) |
| `stellereum-contracts/` | STS-20 tokens, DNS names, liquidity pools, account objects | [README](stellereum-contracts/README.md) · [contracts overview](docs-site/contracts/overview.md) |
| `stellereum-upgrader/` | Cosmovisor-like staged supervisor for node upgrades | [upgrade runbook](docs-site/nodes/upgrades.md) |
| `stellereum-ledger-tool/` | Offline block and chain verifier | [usage text](stellereum-ledger-tool/src/main.rs) |
| `scripts/` | Verification gate, cluster operations, observer onboarding, `stelops` | [scripts README](scripts/README.md) · [operations](docs-site/nodes/operations.md) |
| `docs/` | Specs, architecture notes, audits, CI and runbooks | [spec map](docs/specs/00_PROJECT_MAP.md) · [CI](docs/CI.md) |
| `docs-site/` | Documentation portal source | [portal index](docs-site/index.md) · [docs.stellereum.org](https://docs.stellereum.org) |
| `deploy/` | nginx configuration for the docs site | [nginx config](deploy/nginx/docs.stellereum.org.conf) |

## Quickstart

Run these from the repository root unless a step says otherwise.

| Step | Command |
| --- | --- |
| 1. Clone | `git clone https://github.com/stellereum/stellereum.git && cd stellereum` |
| 2. Build | `cd stellereum && cargo build --release --locked` |
| 3. Local deterministic devnet | `./target/release/stellereum devnet --blocks 100` |
| 4. Join testnet as an observer from a snapshot | `cd .. && ./scripts/join-testnet.sh --mode observer` |
| 5. Run the fast verification gate | `./scripts/verify_testnet_ideal.sh --fast` |

Running a node needs **only Rust and a checkout** — no Node, no npm, no web
build. The HTML/CSS/JS trees (`stellereum/site/`, `docs-site/`,
`explorer-site/`, `sdk-js/`) are the optional website, documentation portal,
explorer and TypeScript SDK sources; none of them is on the node's build path.
`--offline` works only with a pre-populated `~/.cargo` cache; a fresh clone
should build online with `--locked`.

The devnet is seeded and clock-free: the same `--seed` produces the same chain
and state root. The observer script writes to `$HOME/stell-observer`, downloads
the current snapshot, prepares a non-validating observer with RPC and state sync,
and prints the start command; add `--start` to launch it immediately. Drop
`--fast` for the full gate (clippy, formatting, tests and the four-node
simulation harness). Library tests are serial under plain `cargo test` because
consensus tests own a process-global PQ registry; use
`cargo test --lib -- --test-threads=1` in `stellereum/`.

## Documentation

| Topic | Link |
| --- | --- |
| Documentation portal | <https://docs.stellereum.org> |
| Overview and status | <https://docs.stellereum.org/get-started/overview> |
| Quickstart | <https://docs.stellereum.org/get-started/quickstart> |
| Architecture | <https://docs.stellereum.org/get-started/architecture> |
| Post-quantum model | <https://docs.stellereum.org/core-concepts/post-quantum> |
| Consensus and finality | <https://docs.stellereum.org/core-concepts/consensus-finality> |
| Sharding and 2PC | <https://docs.stellereum.org/core-concepts/sharding> |
| Native market | <https://docs.stellereum.org/core-concepts/native-market> |
| Smart contracts | <https://docs.stellereum.org/contracts/overview> |
| Observer and validator setup | <https://docs.stellereum.org/nodes/observer> · <https://docs.stellereum.org/nodes/validator> |
| Operations and monitoring | <https://docs.stellereum.org/nodes/operations> · <https://docs.stellereum.org/nodes/monitoring> |
| JSON-RPC and WebSocket/SSE | <https://docs.stellereum.org/api/json-rpc> · <https://docs.stellereum.org/api/websocket-sse> |
| Security status and threat model | <https://docs.stellereum.org/security/status> · <https://docs.stellereum.org/security/threat-model> |
| Protocol and operator references | [PROTOCOL.md](stellereum/PROTOCOL.md) · [OPERATIONS.md](stellereum/docs/OPERATIONS.md) · [RPC.md](stellereum/docs/RPC.md) |
| CI and serial-test rationale | [docs/CI.md](docs/CI.md) |

Public endpoints:

| Service | URL |
| --- | --- |
| JSON-RPC | <https://rpc.stellereum.org> |
| Explorer and indexer API | <https://explorer.stellereum.org> |
| Testnet application | <https://testnet.stellereum.org> |
| Faucet | <https://faucet-testnet.stellereum.org> |
| Documentation | <https://docs.stellereum.org> |

## Security

There is **no independent external audit**. The repository contains internal
review notes, fuzz targets and penetration-test batteries; those are evidence,
not assurance. Assume consensus, bridge, wallet, RPC and indexer bugs exist.

Report suspected vulnerabilities **privately** through the process in
[SECURITY.md](SECURITY.md). Never open a public GitHub issue for a security
finding, post a proof of concept, or discuss it in public channels before a fix
has been coordinated. The policy's contact and PGP fields are still being
finalized; do not fall back to a public report while a private channel is being
established. Testnet coins have no value; do not bridge or custody real assets
with this software.

## Contributing and license

Read [CONTRIBUTING.md](CONTRIBUTING.md) before a large pull request. Keep the
gate green, add regression tests for new behavior, and do not change quorum,
vote-counting, finality, signature-domain or wire-format rules without a spec
update and an audit note. The fast local gate is
`./scripts/verify_testnet_ideal.sh --fast`; the full gate is the same command
without `--fast`.

Stellereum is dual-licensed under **MIT OR Apache-2.0**. License texts live next
to the main crate: [MIT](stellereum/LICENSE-MIT) and
[Apache-2.0](stellereum/LICENSE-APACHE). The operator tools under
`scripts/tools/stelops` are Apache-2.0.

## What is not here yet

- **No mainnet.** Testnet STELL is for testing only and has no monetary value.
- **No external audit and no standing bug bounty.** `SECURITY.md` defines a
  private disclosure policy, but its contact and PGP fields are still
  placeholders; third-party assurance and a bounty do not exist.
- **Shard 1 is parked.** The fixed `{0,1}` pair is implemented and tested in one
  process, but no live shard-1 traffic is produced. No split or merge has ever
  run on a live network.
- **No production bridge.** Bridge code and tests exist, but no trustless bridge
  is live; bridge withdrawals are testnet software outside any production
  guarantee.
- **No EVM execution.** `eth_*` is a read-only compatibility adapter for chain
  identity, balances and routing. There is no EVM interpreter or EVM state trie,
  and EVM contract creation and calldata execution are refused.
- **zkML is not zero-knowledge.** The opcodes are honest re-execution
  attestations with a Merkle trace. They do not hide inputs, compress proofs, or
  provide a succinct argument.

## Community

- X: <https://x.com/stellereum>
- GitHub: <https://github.com/stellereum/stellereum>
- Telegram: <https://t.me/stellereum>
