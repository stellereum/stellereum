<p align="center">
  <img src="docs/brand/logo-white.svg#gh-dark-mode-only" width="150" alt="Stellereum logo"/>
  <img src="docs/brand/logo-black.svg#gh-light-mode-only" width="150" alt="Stellereum logo"/>
</p>

<h1 align="center">stellereum</h1>

<p align="center">
  <strong>The Stellereum node: consensus, execution, state, RPC and CLI in one Rust binary.</strong><br/>
  Falcon-512 votes and transactions · BFT single-block finality · WASM contracts · native CLOB/PMM.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License: MIT OR Apache-2.0"/></a>
  <a href="https://testnet.stellereum.org"><img src="https://img.shields.io/badge/status-public%20testnet-yellow" alt="Public testnet"/></a>
  <img src="https://img.shields.io/badge/language-Rust-000?logo=rust" alt="Rust"/>
  <a href="docs/audits/EXTERNAL_AUDIT_BRIEF.md"><img src="https://img.shields.io/badge/external%20audit-none%20completed-critical" alt="No external audit completed"/></a>
</p>

> [!WARNING]
> **Testnet only — no independent external audit.** This crate runs the public
> Stellereum testnet. Testnet STELL has no value and state may be reset. The
> code has had internal review, fuzzing and penetration-test batteries, not a
> third-party audit. Do not use it to custody real assets.

This crate is the canonical Stellereum node. A single process runs one shard or
the fixed shard pair `{0,1}`, participates in BFT consensus, executes native
operations and `wasmi` contracts, commits a deterministic state root, and serves
JSON-RPC, WebSocket and SSE. It links the QUIC + DHT transport from
[`infnode`](../infnode/README.md); there is no external consensus or execution
client.

## Architecture

```text
                         wallets · SDKs · explorer · indexer
                                      │
                          HTTPS / JSON-RPC · WS/SSE
                                      │
┌─────────────────────────────────────▼─────────────────────────────────────┐
│                              stellereum node                              │
│                                                                           │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌────────────┐  │
│  │  JSON-RPC    │   │   mempool    │   │  consensus   │   │    P2P     │  │
│  │  stell_*     │──▶│  admission   │──▶│  BFT rounds  │◀─▶│  infnode   │  │
│  │  + EVM read  │   │  nonce/fee   │   │  votes · QC  │   │ ML-KEM-768 │  │
│  └──────────────┘   └──────────────┘   └──────┬───────┘   └────────────┘  │
│                                               │ commit                     │
│                                        ┌──────▼───────┐                   │
│                                        │   execution  │                   │
│                                        │ native ops + │                   │
│                                        │ wasmi (WASM) │                   │
│                                        └──────┬───────┘                   │
│                                               │ effects                    │
│                                        ┌──────▼───────┐                   │
│                                        │ state engine │                   │
│                                        │ accounts +   │                   │
│                                        │   domains    │                   │
│                                        └──────┬───────┘                   │
│                                               │                            │
│                                        ┌──────▼───────┐                   │
│                                        │ local store  │                   │
│                                        └──────────────┘                   │
└───────────────────────────────────────────────────────────────────────────┘
```

### Crate layout

| Path | Responsibility |
| --- | --- |
| `src/main.rs`, `src/lib.rs` | Binary entry point, node startup, library surface |
| `src/consensus/` | BFT state machine, proposer sortition, validator-set rotation, quorum certificates, vote types |
| `src/runtime/` | Per-height driver, apply pipeline, execution lanes, anchors, cluster coordination |
| `src/state_engine/` | 32-byte accounts and committed domains: balances, nonces, staking, contracts, settlement, cross-shard state |
| `src/sharding/` | Blocks, envelopes, shard topology, routing prefixes, cross-shard transaction shapes |
| `src/svm.rs`, `src/contract.rs`, `src/contract_abi.rs`, `src/contract_source.rs` | `wasmi` execution, contract lifecycle, deterministic ABI, source verification |
| `src/rpc/` | JSON-RPC, WebSocket/SSE, faucet, EVM-compatible read adapter, auth and rate limits |
| `src/node/` | Bootstrap, consensus driver, sync, admission policy, upgrade halt marker |
| `src/network.rs`, `src/consensus_net.rs`, `src/data_plane*.rs`, `src/dns_seeds.rs` | Gossip, consensus networking, repair, DNS seed discovery on top of `infnode` |
| `src/storage.rs`, `src/sync.rs`, `src/snapshot_v4.rs`, `src/mmr.rs` | Durable blocks and receipts, snapshots, state sync, Merkle mountain range |
| `src/staking.rs`, `src/governance.rs`, `src/tokenomics.rs`, `src/token.rs` | Bonding, delegation, jailing, slashing, governance, fees and supply |
| `src/orderbook.rs`, `src/pmm.rs`, `src/oracle.rs` | Native CLOB, primary market maker, price oracle |
| `src/bridge.rs`, `src/bridge_adapters.rs`, `src/xshard2pc.rs` | Bridge state machines and two-phase cross-shard value |
| `src/post_quantum.rs`, `src/pq_registry.rs`, `src/wallet*.rs`, `src/node_keys.rs`, `src/remote_signer.rs` | Falcon-512/ML-KEM primitives, on-chain PQ key registry, wallets, encrypted node keys, remote signing |
| `src/zkml.rs`, `src/zkml_attestation.rs` | Re-execution attestations with a Merkle trace |
| `src/cli/` | Command tree, handlers, transaction builders |

The state root is a deterministic commitment over the account trie and the
committed domains. Two nodes at the same height with different roots are on
different chains; the node reports the divergence rather than choosing a side.

## Consensus flow

Stellereum uses weighted BFT with explicit rounds. The live testnet runs four
equal-power validators, so the quorum is three of four.

```text
PROPOSE ──▶ PREVOTE ──▶ PRECOMMIT ──▶ COMMIT
   │           │            │            │
   │           │            │            └─ block final; effects applied
   │           │            └─ precommit certificate is the quorum proof
   │           └─ validators verify the proposal and vote for its hash
   └─ scheduled proposer broadcasts a block for this height and round
```

1. **Proposer selection.** The proposer for `(height, round, validator set)` is
   deterministic. A node cannot choose itself.
2. **Proposal.** The proposer assembles a block from its local mempool. Block
   timestamps must extend the parent monotonically and stay within the
   deterministic drift bound; a body and header are committed separately.
3. **Prevote.** Validators verify the block, the proposer signature, the parent,
   the timestamp and the state transition. A validator locked on a value
   prevotes that value or nil, never a conflicting block.
4. **Precommit.** A prevote quorum for the same block authorises a precommit.
   Precommits are individually Falcon-512-signed.
5. **Commit and apply.** A precommit quorum of `floor(2 · power / 3) + 1` makes
   the block final. Application order is fixed; native effects and contract
   effects commit together, and receipts record the verdict, gas and events.

Safety comes from locking and quorum intersection. Liveness comes from round
timeouts and a rotating proposer. A peer message may advance the local round by
at most one; a far-round claim is not allowed to drag a node into a round whose
proposer nobody serves. An empty or zero-power validator set returns an
unreachable quorum, never `1`.

With four equal validators, one may be offline and the chain still finalizes.
Two offline and it stalls at the last finalized height rather than producing a
shorter or conflicting history. Finalized blocks do not roll back.

Further reading: [consensus and finality](../docs-site/core-concepts/consensus-finality.md),
[BFT comparison](../docs/BFT_COMPARISON.md), and the protocol entry point
[`PROTOCOL.md`](PROTOCOL.md).

## Post-quantum model

The threat model assumes a quantum adversary can forge classical signatures.
Stellereum therefore uses post-quantum cryptography for consensus votes and
value-moving transactions, with no classical fallback lane.

| Purpose | Primitive | Encoding |
| --- | --- | --- |
| Transaction and vote signatures | **Falcon-512** | 897-byte public key, 666-byte signature, `PQ1` envelope |
| Transport key exchange | **ML-KEM-768** | Encapsulation key held by the node; per-handshake ephemeral KEM |
| Peer authentication | **Falcon-512** | P2P identity separate from the consensus key |
| Validator name | 32-byte validator id | Derived from the cold withdrawal address and initial voting key |

### The `PQ1` envelope

Every Falcon signature travels in `PQ1`: a strict scheme id (`0x02` for
Falcon-512), an explicit or implicit public-key mode, a salt, the signature and
an optional trailing chain id. The decoder pins lengths to the scheme. An
explicit envelope carries exactly one 897-byte key; an implicit envelope carries
none and relies on the node's key registry. The first spend from a new account
uses the explicit form; later transactions may omit the key as a bandwidth
optimisation, never as a trust shortcut.

When a chain id is present it is appended to the envelope and included in the
signed message. A signature made for another chain, or an envelope replayed with
a different id, fails verification. The live network is chain id `5757`.

### Validator key separation

A validator has three distinct roles:

- a **cold withdrawal key** that controls stake and authorises withdrawal;
- a **hot voting key** that signs consensus votes and carries a proof of
  possession;
- an immutable 32-byte **validator id** used as the stable voter name.

The hot key can be rotated after an on-chain announcement and a delay; the cold
key authorises the rotation. A validator's vote is still a Falcon-512 signature,
not an Ed25519 signature. Ed25519 is not a signing lane; it survives at most as
the organisational shape of the 32-byte validator id.

There is no dual-stack mode on a running node: a classical transaction is
refused at intake with `invalid transaction signature`, not downgraded. For the
full envelope layout and key hierarchy, see
[post-quantum](../docs-site/core-concepts/post-quantum.md) and
[`docs/specs/02_CRYPTO_AND_PQ.md`](../docs/specs/02_CRYPTO_AND_PQ.md).

## Execution and the native market

Contracts are WebAssembly modules executed by `wasmi` under a fuel meter. The
interface is integer-only and deterministic: every export takes and returns
`i64`, dispatch is by method name and exact arity, and there are no floats,
clock reads, filesystem calls or host memory access.

The host interface is closed. It registers 14 functions today: the original 13
(`sload`, `sstore`, `emit`, `caller`, `value`, `block_time`, `block_hash`,
`calldata`, `return_data`, `sha256`, `blake3`, `falcon512_verify`,
`send_message`) plus `origin`. Anything else is an unresolvable import and the
module fails to deploy. `ed25519_verify` was removed, not stubbed.

| Limit | Value |
| --- | --- |
| Contract code | 2 MiB |
| Linear memory | 128 pages |
| Storage keys | 4,096 |
| Events per call | 256 |
| Outbound messages per call | 64 |
| Call arguments | 8 |
| Call depth | 8 |
| Read-only getter fuel | 5,000,000 |

Fuel is charged **before** an effect: a storage write, event, outbound message
or cryptographic verification cannot happen and then run out of fuel. A failed
call rolls back its effects. Deployment and calls are transactions, not RPC side
effects; `stell_deployContract` and `stell_callContract` are previews that
validate and simulate.

The base layer also carries:

- a **native CLOB** with price-time priority and committed order books;
- a **primary market maker** implementing a bonding-curve mint/redeem exchange;
- **account objects** and scoped **session keys** with expiry, gas budget and
  terminal revocation;
- a governed **bridge** and a price **oracle** with circuit breakers;
- **zkML** opcodes that re-execute the model on every node and compare outputs
  against a BLAKE3 Merkle trace root. This is honest re-execution, **not** a
  zero-knowledge proof: it is neither succinct nor hiding.

The EVM surface is a read-only compatibility adapter. `eth_chainId`,
`eth_getBalance` and related reads work; there is no EVM interpreter, no EVM
state trie, and EVM contract creation or calldata execution is refused.

## JSON-RPC

The node serves JSON-RPC 2.0 over HTTP `POST` on `STELL_RPC_LISTEN` (default
`127.0.0.1:8545`). A second listener on `STELL_EXPLORER_LISTEN` (default
`127.0.0.1:8080`) exposes the same router at `/rpc` behind the gateway rate
limiter, plus `/healthz`, `/readyz`, `/metrics` and `/api/*`.

| Surface | Purpose |
| --- | --- |
| `stell_*` | Native chain namespace: chain identity, blocks, balances, transactions, validators, staking, governance, contracts, market, bridge, proofs |
| `eth_*` | Read-only EVM-compatible adapter for chain id, balances and routing |
| `GET /ws` | WebSocket subscriptions |
| `GET /events` | Server-sent events |

Batches are bounded (64 items, 1 MiB). Ordinary reads are open; governance
writes and contract previews require `STELL_RPC_AUTH_TOKEN` on every bind,
including loopback. `stell_mempoolDump` and the wallet signing arms are
fail-closed without a token. The faucet requires its own `STELL_FAUCET_TOKEN`
and is disabled unless `STELL_FAUCET=1` and a key file is configured.

```bash
curl -sS http://127.0.0.1:8545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":[]}'
# {"jsonrpc":"2.0","id":1,"result":5757}
```

Full method reference: [`docs/RPC.md`](docs/RPC.md) and the
[JSON-RPC guide](../docs-site/api/json-rpc.md).

## CLI

The `stellereum` binary exposes node, wallet, market, light-client, governance
and validator commands. Every network command accepts `--rpc`, most signing
commands accept `--chain-id`, `--nonce`, `--dry-run` and `--token`.

| Group | Commands |
| --- | --- |
| Node lifecycle | `run`, `node-bootstrap`, `devnet`, `sim`, `sim-replay`, `keys`, `safety-init`, `upgrade-status`, `network` |
| Wallet | `wallet generate`, `wallet balance`, `wallet address`, `wallet send-pq`, `wallet delegate-session`, signing and verification helpers |
| Market | `orderbook`, `pmm`, `oracle` |
| Bridge | `bridge` |
| Light client | `light-client`, `light-anchor`, `light-verify`, `light-rotate` |
| Governance | `gov list`, `gov show`, `gov params`, `gov propose`, `gov vote` |
| Validator | `validator register-validator`, `rotate-voting-key`, `change-withdrawal`, `claim-withdrawal`, `announce-commission`, `apply-commission`, `status`, `stake`, `unbond`, `withdraw`, `delegate`, `begin-undelegate`, `withdraw-delegation`, `claim-rewards`, `unjail` |

Use `wallet send-pq` for value. The legacy `wallet send` builds an Ed25519
transaction, which a pure-PQ node refuses; it exists for historical/dev flows,
not for the live network.

### Governance

`gov` builds block-carried `SysCallGovPropose` and `SysCallGovVote`
transactions, signs them with a Falcon-512 key, and submits them through
JSON-RPC. Reads need no token; submission needs the node's write token because
governance writes are token-gated on every bind.

```bash
# Current quorum, next proposal id and applied overrides
stellereum gov params --rpc https://rpc.stellereum.org

# Submit a signal proposal
stellereum gov propose \
  --falcon-key-file keys/falcon.key \
  --title "Signal: testnet parameter review" \
  --action signal \
  --params '{"text":"review the next fee schedule"}' \
  --rpc https://rpc.stellereum.org \
  --chain-id 5757 \
  --token "$STELL_RPC_AUTH_TOKEN"

# Vote yes on proposal 1
stellereum gov vote \
  --falcon-key-file keys/falcon.key \
  --id 1 --choice yes \
  --rpc https://rpc.stellereum.org \
  --chain-id 5757 \
  --token "$STELL_RPC_AUTH_TOKEN"
```

Supported action types include `signal`, `set_min_gas_limit` and
`software_upgrade`; parameters are JSON and are validated before signing.
Proposals have a three-day voting period and a 90,000-height timelock before
execution.

### Validator lifecycle

`validator` covers the post-v7 three-key lifecycle and the staking operations
that surround it. The hot voting key signs votes; the cold withdrawal key signs
stake movement, key rotation, commission changes and unjail.

```bash
# Read on-chain status, stake, jail state and withdrawal balance
stellereum validator status \
  --validator <32-byte-validator-id> \
  --rpc https://rpc.stellereum.org

# Register a new validator (amounts are nano-STELL)
stellereum validator register-validator \
  --withdrawal-key-file keys/withdrawal.key \
  --voting-key-file keys/falcon.key \
  --amount 2000000000000 \
  --commission-bps 1000 \
  --rpc https://rpc.stellereum.org \
  --chain-id 5757 \
  --token "$STELL_RPC_AUTH_TOKEN"

# Re-admit a downtime-jailed validator under the cold withdrawal key
stellereum validator unjail \
  --withdrawal-key-file keys/withdrawal.key \
  --validator-id <32-byte-validator-id> \
  --rpc https://rpc.stellereum.org \
  --chain-id 5757 \
  --token "$STELL_RPC_AUTH_TOKEN"
```

`rotate-voting-key` and `change-withdrawal` require a proof of possession over
the new key. `announce-commission` starts the delay; `apply-commission` applies
the matured change. All mutating commands support `--dry-run`, which prints the
signed transaction instead of submitting it.

## Configuration

The node reads an infnode YAML file (default `config.yaml`; generated examples
are under [`testnet/`](testnet/)) and a set of environment variables. The YAML
names the node, its QUIC listen address, advertised endpoint and pinned peers.
Environment variables decide the chain, shard set, RPC bind, retention and
operator secrets.

| Variable | Default | Meaning |
| --- | --- | --- |
| `STELL_CHAIN_ID` | `5757` | Effective chain id. A connected peer reporting another id is refused, never silently partitioned |
| `STELL_SHARDS` | unset (single shard) | Shards this process runs. `0` is the masterchain; `0,1` is the only supported multi-shard set and must run in one process. Other sets require the experimental hatch and are off |
| `STELL_MIN_BLOCK_MS` | `50` | Local floor between blocks, in milliseconds. The live testnet sets `400`. `0` disables the floor. Not a consensus rule |
| `STELL_RPC_LISTEN` | `127.0.0.1:8545` | JSON-RPC bind. Keep loopback unless a token and a proxy are in place |
| `STELL_EXPLORER_LISTEN` | `127.0.0.1:8080` | Gateway/explorer bind: `/rpc`, `/healthz`, `/readyz`, `/metrics`, `/api/*` |
| `STELL_DNS_SEEDS` | unset | Comma-separated seed domains for DNS TXT peer discovery. Discovery peers are never added to the validator set |
| `STELL_OBSERVER` | unset | `1` runs a non-validating observer. A fresh join must start as an observer, sync, then be promoted |
| `STELL_ARCHIVE` | archive | Archive mode is the default. `0` or `false` enables pruning |
| `STELL_KEEP_BLOCKS` | `50000` | Body window in prune mode; ignored in archive mode |
| `STELL_SNAPSHOT_INTERVAL` | `1000` | Heights between state/domain snapshots; minimum 50 |
| `STELL_RPC_AUTH_TOKEN` | unset | Gates operator/write methods (mempool dump, wallet signing, governance writes, contract previews). Transaction submission is open by design. A non-loopback bind without it is loud and unsafe |
| `STELL_KEY_PASSPHRASE` | unset | Passphrase for encrypted node keys (`enc2:` Argon2id + XChaCha20-Poly1305). Back it up with `./keys` |
| `STELL_FAUCET` | off | `1` enables the faucet endpoint. Requires `STELL_FAUCET_KEY_FILE` and `STELL_FAUCET_TOKEN`; fails closed otherwise |
| `STELL_FAUCET_LIFETIME_CAP_STELL` | `50` | Per-address lifetime faucet cap, in whole STELL |
| `STELL_PUBLIC_DRIP_NANO` | `2000000000` | Public drip amount, in nano-STELL (2 STELL) |
| `STELL_PUBLIC_DRIP_COOLDOWN_SECS` | `2700` | Public per-address drip cooldown (45 minutes) |
| `STELL_FAUCET_IP_MAX_PER_HOUR` | `20` | Per-IP hourly drip budget |

Genesis inputs must match on every node: the validator set, the shard set and
the faucet key seed all feed the genesis state root. A node that starts with a
different value derives a different chain and is refused or isolated. Back up
`./keys` and the passphrase together; losing the passphrase loses the node
identity. See [`NODE.md`](NODE.md) and
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) for the full operator procedure.

## Local devnet and tests

```bash
cd stellereum
cargo build --release --offline

# Deterministic devnet: same seed, same chain and state root
./target/release/stellereum devnet --seed 00 --blocks 100

# Optional: write a transaction log and final state snapshot for replay
./target/release/stellereum devnet \
  --seed 00 --blocks 100 \
  --log /tmp/stell-devnet.jsonl \
  --snapshot /tmp/stell-devnet.snapshot

./target/release/stellereum sim-replay --log /tmp/stell-devnet.jsonl

# In-process multi-validator simulation
./target/release/stellereum sim --blocks 5
```

The devnet never reads the wall clock and never uses OS randomness: timestamps
are logical and every key is derived from `--seed`. `sim-replay` rebuilds the
genesis from the seed in the log, re-applies every block and fails if the final
state root differs from the recorded one.

```bash
# Library suite: serial because consensus tests own a process-global PQ registry
cargo test --lib -- --test-threads=1

# Focused consensus and state suites
cargo test --test consensus_byzantine_tests
cargo test --test liveness_horizon_tests
cargo test --test state_root_completeness_tests

# Lints are a gate
cargo clippy --all-targets -- -D warnings

# Full repository gate (from the repository root)
../scripts/verify_testnet_ideal.sh --fast
```

The serial requirement is deliberate and documented in
[`../docs/CI.md`](../docs/CI.md): several consensus tests replace the
process-global committed PQ registry, so parallel plain `cargo test` runs can
erase another test's validator keys. `cargo nextest` runs each test in its own
process and does not need the flag. Do not weaken assertions to make a parallel
run pass.

## Operations

| Port | Protocol | Purpose |
| --- | --- | --- |
| `9410/udp` | QUIC | P2P transport; must be reachable inbound for a validator |
| `8545/tcp` | HTTP | JSON-RPC; bind loopback unless a token and proxy are in place |
| `8080/tcp` | HTTP | Explorer/gateway, health, readiness, metrics and `/api/*` |

Common operator entry points:

- [Node setup and ports](NODE.md)
- [Validator onboarding](VALIDATOR.md) and
  [validator guide](../docs-site/nodes/validator.md)
- [Operations runbook](docs/OPERATIONS.md) and
  [operations guide](../docs-site/nodes/operations.md)
- [Multi-node testnet stand](testnet/README.md)
- [Observer onboarding](../scripts/join-testnet.sh) and
  [cluster scripts](../scripts/README.md)
- [Monitoring](../docs-site/nodes/monitoring.md) and
  [upgrades](../docs-site/nodes/upgrades.md)
- [JSON-RPC reference](docs/RPC.md)
- [CI and test policy](../docs/CI.md)

A fresh observer should use `node-bootstrap` with a clean data directory,
`STELL_OBSERVER=1`, a live peer pointer and the network's faucet key. The
preflight refuses a dirty directory, a missing peer pointer, a missing faucet
key or a missing validator set, because each of those can silently produce a
private chain instead of a join.

## Security and license

There is no independent external audit. Internal review, fuzz corpora and
pentest batteries are in-tree; they are evidence, not assurance. Report
suspected vulnerabilities privately through [`SECURITY.md`](SECURITY.md) and
never open a public issue with a proof of concept. Threat model and known issues:
[`docs/audits/THREAT_MODEL.md`](docs/audits/THREAT_MODEL.md),
[`docs/audits/KNOWN_ISSUES.md`](docs/audits/KNOWN_ISSUES.md) and the
[public security status](../docs-site/security/status.md).

Stellereum is dual-licensed under **MIT OR Apache-2.0**. See
[`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).
