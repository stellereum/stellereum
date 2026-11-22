# Overview

Stellereum (STELL) is a **pure post-quantum, sharded, non-EVM Layer 1 written in Rust**. Validator votes and wallet transactions are signed with **Falcon-512**; transport is protected with **ML-KEM-768**. Classical signature schemes are not accepted for value, and in consensus and value transfer Ed25519 survives only as a 32-byte validator identity and voter id.

The network is in **public testnet**. It has had internal review, but **no independent external audit has been completed**. Do not use real funds.

## At a glance

| Property | Value |
| --- | --- |
| Chain ID | **5757** (`0x167d`) |
| Consensus ruleset | **v7** |
| Fork ID | **`0x3ae00ebc`** |
| Native token | STELL, 9 decimals (1 STELL = 10⁹ nano-STELL) |
| Signatures | Falcon-512 only (PQ1 transaction envelope; Falcon consensus votes); no classical/Ed25519 signature lane |
| Transport | ML-KEM-768 encapsulation keys |
| Consensus | BFT propose → prevote → precommit → commit |
| Quorum | `floor(2 · power / 3) + 1` |
| Finality | Single block: one finalized block is final |
| Live block tempo | Configured with `STELL_MIN_BLOCK_MS=400` |
| Execution | WASM on `wasmi`, pure `(i64) -> i64`, 14 host functions |
| Sharding | masterchain shard 0 live; fixed `{0,1}` pair supported, shard 1 parked |
| Native market | On-chain CLOB + PMM, session keys, account objects |
| zkML | Re-execution attestations with a Merkle trace — **not** zero-knowledge proofs |

## What "pure post-quantum" means here

Every consensus vote carries a Falcon-512 signature over the vote preimage, and every value-moving wallet transaction carries a Falcon-512 signature inside a `PQ1` envelope. There is no fallback to Ed25519, secp256k1, or a hybrid lane: a node running in pure-PQ mode refuses a classical transaction instead of silently accepting it.

The one Ed25519 survivor in consensus and value transfer is organizational, not financial: a validator has a 32-byte **validator id / voter id** derived from Ed25519 key material, while its vote is signed with the hot Falcon-512 voting key and its stake is controlled by the cold Falcon-512 withdrawal key. The vote frame still carries a legacy Ed25519 half for wire compatibility; the pure-PQ verifier ignores it and checks only the Falcon half. Losing that separation is a security bug, not a supported configuration. Separately, the wallet message-signing standard supports Ed25519 for off-chain statements; such a signature can never be replayed as a transaction (see [Wallets & signing](/sdk/wallets-and-signing)).

See [Post-quantum](/core-concepts/post-quantum) for the envelope layout and the exact key hierarchy.

## Design choices that differ

- **Finality is one block.** A block that carries a precommit quorum is final. There is no probabilistic confirmation window and no reorg safety budget to wait out. See [Consensus & finality](/core-concepts/consensus-finality).
- **The base layer has a market.** A central limit order book and a primary market maker are protocol features, not an application deployed on top. See [Native market](/core-concepts/native-market).
- **Contracts are deterministic integer WASM.** `wasmi` executes modules with no floats, no nondeterminism, and fuel charged before each effect. See [Smart contracts](/contracts/overview).
- **Sharding is a committed design, not a claim of live scale.** The `{0,1}` pair is supported and tested in one process; today the public network runs shard 0 only. See [Sharding](/core-concepts/sharding).
- **zkML is not zero-knowledge.** The verify opcodes re-execute the model on every node and compare outputs. They do not produce or verify a succinct proof.

## Endpoints

| Service | URL |
| --- | --- |
| JSON-RPC | `https://rpc.stellereum.org` |
| Explorer and indexer API | `https://explorer.stellereum.org` |
| Testnet application | `https://testnet.stellereum.org` |
| Faucet | `https://faucet-testnet.stellereum.org` |
| Documentation | `https://docs.stellereum.org` |

The RPC is POST-only JSON-RPC. The native namespace is `stell_*`; a read-only EVM adapter is served on the same endpoint for chain-id and balance interoperability, but it does not execute EVM bytecode and cannot move value on its own. Details are in [Networks](/get-started/networks) and the [JSON-RPC reference](/api/json-rpc).

## Choose a path

| You are a… | Start with |
| --- | --- |
| **Developer** | [Quickstart](/get-started/quickstart) → [Architecture](/get-started/architecture) → [Contracts](/contracts/overview) |
| **Validator** | [Validator setup](/nodes/validator) → [Consensus](/core-concepts/consensus-finality) → [Operations](/nodes/operations) |
| **Wallet or exchange integrator** | [Addresses](/get-started/addresses) → [Accounts & fees](/core-concepts/accounts-and-fees) → [JSON-RPC](/api/json-rpc) |
| **Auditor** | [Security status](/security/status) → [Threat model](/security/threat-model) → [Consensus](/core-concepts/consensus-finality) |

## Status and limitations

::: warning Testnet only — no external audit
Stellereum is not mainnet. The codebase has passed internal review waves; an independent external audit has **not** been completed. Testnet state, parameters, addresses and endpoints may change or be reset without notice. Do not deposit real value, do not reuse production keys, and do not treat uptime as a service-level commitment.
:::

Known scope limits that matter before you build:

- **Shard 1 is parked.** The code supports the fixed pair `{0,1}`, and cross-shard transfers use two-phase commit, but only shard 0 is live on the public network.
- **No EVM execution.** There is no EVM interpreter and no EVM state trie. EVM JSON-RPC methods exist for compatibility and read-only routing; contract calls and contract creation are refused.
- **zkML is not ZK.** The opcodes prove correct re-execution. They do not hide inputs, compress proofs, or provide a succinct argument.
- **One live validator set.** Testnet validator membership and governance are operated by the project. Permissionless validator onboarding is not a production guarantee.

## Next

Begin with the [Quickstart](/get-started/quickstart) for a funded transfer, then read [Architecture](/get-started/architecture) for the lifecycle behind it. [Networks](/get-started/networks) lists every live endpoint.
