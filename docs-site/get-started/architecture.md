# Architecture

Stellereum is a single Rust node binary that combines consensus, execution, state, RPC, and P2P transport. A node can run one shard or the fixed shard pair `{0,1}` in one process. There is no separate sequencer, no external execution client, and no EVM interpreter.

## Process topology

```text
                         wallets · SDKs · explorer · indexer
                                      │
                          HTTPS / JSON-RPC (POST) · WS/SSE
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
│                                        │ 16 domains   │                   │
│                                        └──────┬───────┘                   │
│                                               │                            │
│                                        ┌──────▼───────┐                   │
│                                        │ local store  │                   │
│                                        └──────────────┘                   │
└───────────────────────────────────────────────────────────────────────────┘
```

## Shards and the masterchain

```text
                    ┌────────────────────────────────────────────┐
                    │  MASTERCHAIN — shard 0                     │
                    │  accounts · staking · governance · CLOB    │
                    │  validator set · shard-head commitments    │
                    │  cross-shard coordination (2PC hub)        │
                    └───────────────┬────────────────────────────┘
                                    │  TON-style longest-prefix routing
                    ┌───────────────▼────────────────────────────┐
                    │  WORKCHAIN — shard 1                       │
                    │  workchain accounts · tokens · contracts   │
                    │  supported, currently PARKED               │
                    └────────────────────────────────────────────┘
```

- **Shard 0 is the masterchain.** It carries the account ledger, staking, governance and the native CLOB. The public testnet runs shard 0.
- **Shard 1 is a workchain.** The fixed pair `{0,1}` is a supported configuration (`STELL_SHARDS=0,1`) and runs in one process per node. It is parked on the public network today: the code path exists and is tested, but no live shard-1 traffic is being produced.
- **Any other shard set is experimental and off.** Arbitrary multi-shard topologies require the experimental hatch and are not part of this network.

Read [Sharding](/core-concepts/sharding) for the routing rule, the two-phase commit, and what a split would require.

## Components

| Component | Responsibility |
| --- | --- |
| **JSON-RPC** | `stell_*` native namespace, subscriptions, and a read-only EVM adapter on the same listener |
| **Mempool** | Signature and envelope validation, fee floor, nonce ordering, duplicate and quota checks |
| **Consensus** | Propose → prevote → precommit → commit, vote verification, quorum certificates, round and view changes |
| **Execution** | Native opcodes plus `wasmi` contract execution; fuel is charged before an effect is applied |
| **State engine** | 32-byte accounts (`balance`, `nonce`) and committed domains: tokens, staking, PMM, contracts, escrow, governance, oracle, session keys, books, bridge, cross-shard, XPC, zkML, CN/VRF, EVM bindings, PQ registry |
| **State root** | Deterministic commitment over the account trie and per-domain commitments; equal height with a different root means a split |
| **P2P transport** | infnode over QUIC/UDP with ML-KEM-768 encapsulation keys and a Falcon P2P identity |
| **Local store** | Durable blocks, receipts, consensus safety state and domain data |
| **Explorer / indexer** | Separate services that consume RPC and serve query APIs; they are not consensus participants |

## Transaction lifecycle

A transfer moves through the same path whether it is sent by a wallet, the faucet or a contract:

1. **Build.** The wallet constructs a `Transaction` with `from`, `to`, `amount`, `gas_limit`, `nonce`, `source_shard`, `target_shard`, `payload`, and a Falcon-512 signature inside a `PQ1` envelope. The signing message is chain-bound when a chain id is supplied.
2. **Admission.** The receiving node checks the envelope and signature, derives the sender address from the Falcon public key, enforces the base-fee floor, checks `amount + gas_limit` solvency, rejects duplicates and nonce gaps, and applies per-sender and pool quotas.
3. **Gossip.** Admitted transactions propagate to the other validators' mempools. Each node's mempool is local; a transaction that is `pending` on one node may be unknown on another.
4. **Propose.** The scheduled proposer assembles a block. Blocks are bounded by transaction count and gas.
5. **Prevote.** Validators verify the proposal and broadcast a prevote for the block hash. A validator that is locked on a block does not prevote a conflicting one.
6. **Precommit.** Once a prevote quorum exists for the same block, validators broadcast a precommit. The precommit certificate is the quorum proof.
7. **Commit and apply.** The block is applied in a fixed order. Native effects and contract effects are committed together; receipts record the verdict, gas used, fee charged and events.
8. **Finality.** A block with a precommit quorum of `floor(2 · power / 3) + 1` is final. One finalized block is final; later blocks add operational depth, not reorg safety.

The same ordering rule applies to cross-shard value, with one extra phase: the source shard escrows the debit in `PREPARE`, the target acknowledges with `PREPARE-ACK`, and `COMMIT` performs the single credit. A duplicate `COMMIT` is a no-op, and a committed transfer has no refund path by design — the protocol burns rather than risk a double spend.

## What the architecture deliberately does not include

- **No EVM interpreter.** EVM JSON-RPC is an adapter for chain-id, balances and routing. It cannot deploy or execute EVM bytecode.
- **No classical signature path.** Ed25519 is not a transaction signature scheme. See [Post-quantum](/core-concepts/post-quantum).
- **No external consensus client.** Consensus and execution share one binary and one state; there is no ABCI-style split.
- **No trustless bridge assumption.** Bridge withdrawals rely on committed proofs and governance; the bridge is testnet software and is outside the scope of these first two sections.

## Next

Start with the [Quickstart](/get-started/quickstart) to run this architecture against the testnet. [Consensus & finality](/core-concepts/consensus-finality) explains why one block is final.
