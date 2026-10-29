# 🏛 Stellereum Network (STELL)

<p align="center">
  <img src="https://raw.githubusercontent.com/stellereum/assets/main/banner.png" alt="Stellereum Banner" width="100%" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <strong>Ultra-High Performance L1 Multi-Blockchain Architecture</strong><br/>
  <em>Lightweight, AI-Native, MEV-Resistant & Orderbook-Optimized Financial Core</em>
</p>

<p align="center">
  <a href="#-key-features"><img src="https://img.shields.io/badge/Architecture-TON%20Core%20%2B%20Lightweight-0088cc?style=for-the-badge&logo=telegram" alt="Architecture"/></a>
  <a href="#-benchmarks"><img src="https://img.shields.io/badge/Block%20Latency-%3C120ms%20(target)-success?style=for-the-badge" alt="Latency"/></a>
  <a href="#-security"><img src="https://img.shields.io/badge/Tests-999%20passing-brightgreen?style=for-the-badge" alt="Tests"/></a>
  <a href="#-tokenomics"><img src="https://img.shields.io/badge/Native%20Token-STELL-blue?style=for-the-badge" alt="Token"/></a>
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-orange?style=for-the-badge" alt="License"/></a>
</p>

---

## 📖 Overview

**Stellereum** is a next-generation Layer-1 multi-blockchain designed from the ground up for high-frequency trading (HFT), autonomous AI agents, and frictionless capital onboarding from external networks (TON, Arbitrum, Ethereum, Solana).

Built natively in **Rust** on top of the **infnode** peer-to-peer transport layer (QUIC / TLS with forward secrecy and Kademlia DHT), Stellereum targets **sub-120ms block times** and thousands of orders per second on lightweight hardware (1–2 CPU cores, 4 GB RAM) without requiring heavy TEE/SGX enclaves.

> **Status — measured vs. target.** `<120ms` is an in-process simulator figure, not a measurement of the live stand: the local simulator's first block finalizes in single-digit milliseconds, but the deployed stand currently runs on the order of **seconds per block**, limited by the transport layer. The node enforces an optional production floor, `STELL_MIN_BLOCK_MS` (default 400ms, `testnet/genesis.env:151`); set it to `0` to disable the floor. Treat `<120ms` as a target, not a current guarantee.

---

## ⚡ Core Architectural Pillars

```text
               ┌────────────────────────────────────────────────────────┐
               │              MASTERCHAIN (Shard 0)                     │
               │  - Global Config & Consensus Validator Set             │
               │  - Shared Sequencer & Cross-Shard Hub                  │
               │  - 3-Tier Price Safety Network & Circuit Breaker       │
               └───────────┬────────────────────────────────┬───────────┘
                           │ Tight-Coupling Merkle Routing  │
            ┌──────────────▼──────────────┐  ┌──────────────▼──────────────┐
            │   SHARDCHAIN 1 (Prefix 0*)  │  │   SHARDCHAIN 2 (Prefix 1*)  │
            │ - In-Memory DAG BoC State   │  │ - In-Memory DAG BoC State   │
            │ - CLOB Orderbook-Actors     │  │ - CLOB Orderbook-Actors     │
            │ - Micro-Gas SVM Engine      │  │ - Micro-Gas SVM Engine      │
            └─────────────────────────────┘  └─────────────────────────────┘
```

### 1. Actor Model & TON Core Foundation
* **Independent Parallel Actors:** Every account, order, and smart contract operates as an isolated actor communicating via asynchronous message queues.
* **TON-Style Bounce Semantics:** If an actor call fails or the destination does not exist, funds automatically bounce back to the sender (`bounced = true`).
* **Bag of Cells (BoC) & Patricia DAG:** State is stored in 128-byte cell graphs forming binary Patricia-Merkle trees with complete inclusion proof generation and verification.

### 2. Infinite Dynamic Sharding Paradigm
* Shards automatically split into child shards when transaction throughput exceeds load thresholds (`check_and_split`), and automatically merge when load subsides (`check_and_merge`).

### 3. Native Orderbook-Actor CLOB (In-VM Exchange)
* Central Limit Order Books are implemented as native system actors executing specialized low-level VM instructions.
* Supports Limit and Market orders, partial fills, price-time priority matching, and anti-spam depth caps.

### 4. Micro-Gas Model for AI High-Frequency Trading
* **Basic transfer fee:** ~280,000 nano-STELL (~$0.00007 USD, ~20x under TON).
* **Order cancellation fee:** 100 nano-STELL (~$0.000025 USD).
* Eliminates financial friction for automated market makers and HFT bots.

### 5. Zero-Overhead MEV-Preemption (Threshold Blind Rounds)
* Implements **Shamir's Secret Sharing ($T$-of-$N$)** over the Curve25519 scalar field (`src/mev.rs`).
* Transactions admitted through `Mempool::insert` are sealed under an ephemeral round key and re-opened at block build, and the block build records a signed commitment to the exact execution order that finalize re-verifies.
* **Status caveat:** the full threshold preemption is *deferred*, not active. Per `src/mev.rs`, the round key is **node-local**, so this phase does not hide transactions from the proposer itself; true front-running elimination needs asymmetric round sealing, a validator share-release round, and sealed mempool gossip, none of which have a wire slot today (deliberately left unwired rather than simulated). Do not read the "mathematically eliminated" phrasing as a property of the current code.

### 6. AI-Native VM (SVM + zkML + Session Keys)
* **Consensus-level zkML Verification:** On-chain verification of machine learning inferences ($y = \text{ReLU}(Wx + b)$) with Fiat-Shamir proofs in under 1 ms.
* **Delegated Session Keys:** Autonomous trading bots sign micro-transactions instantly without holding master cold keys, constrained by delegated gas spending caps and expiration time-locks.

### 7. High-Speed Selective Confidentiality
* **Pedersen Commitments:** Curve25519/Ristretto homomorphic value commitments ($\sum C_{\text{in}} - \sum C_{\text{out}} = \text{fee} \cdot G$) prove balance integrity without revealing transaction amounts.
* **Stealth Addresses:** Dual-key Diffie-Hellman one-time addresses shield trader identities from public ledger surveillance.
* **Viewing Keys:** Voluntary cryptographic viewing keys allow regulatory compliance (FATF Travel Rule / institutional fund audits) without compromising spend authority.

### 8. 3-Tier Price Safety Network & Circuit Breaker
* **Tier 1:** Pull-Oracles (Pyth / RedStone style cryptographic calldata updates with $\le 15$ min freshness checks).
* **Tier 2:** 30–60 minute rolling On-Chain DEX TWAP fallback calculator.
* **Tier 3 (Circuit Breaker):** Automated trading and minting freeze if prices deviate by $>10\%$ or if USDT drops below $\$0.95$.

### 9. Native Teleport Bridges
* Direct capital onboarding gateways for **TON, Arbitrum, Ethereum, and Solana**.
* The `TeleportBridgeEngine` (`src/bridge.rs`) enforces a $2/3$ quorum of **distinct** validators on deposits, a 1-hour time-lock on large withdrawals ($\ge 50\,000$ STELL) and an hourly throughput rate limit ($500\,000$ STELL/hr).
* **Status caveat:** the quorum/replay/rate-limit policy is now enforced on the
  live block path, not just in the engine: a deposit must carry 2/3 **distinct**
  validator attestations in the same transaction (`BridgeIntent::Attest`,
  checked at settlement against the committed validator set, empty set fails
  closed), the per-source-tx replay set, the parked withdrawal queue and the
  hourly rate window are committed as a conditional bridge domain (empty
  contributes zero digest bytes, `COMMITMENT_VERSION` stays put), and large
  withdrawals park behind the 1-hour time-lock until `BridgeIntent::Release`
  finalizes them. The external payout itself remains the relayers' job
  (`Release` moves no coins on chain).

---

## 💎 Tokenomics & Genesis Vault

| Parameter | Value |
| :--- | :--- |
| **Native Token** | **STELL** (9 decimal places, nano-STELL) |
| **Total Hard Cap** | **1,000,000,000 STELL** |
| **Genesis Vault Allocation** | **250,000,000 STELL** (25% Public Exchange) |
| **Genesis Mint Price** | **$0.25 USD** fixed base rate |
| **Accepted Inbound Assets** | **USDT** (TON/TRON), **TON**, **GRAM** |

$$\text{STELL} = \frac{\text{Deposited Assets} \times \text{Asset Price (USD)}}{\$0.25}$$

### Token Distribution

```text
┌───────────────────────────────────────────────┐
│ [███████] Validator Staking Rewards   35%     │ (350M STELL, 5-10 year emission)
│ [█████]   Genesis Vault Exchange      25%     │ (250M STELL, $0.25 base price)
│ [███]     Liquidity Pools (DEX/CEX)   15%     │ (150M STELL, STELL/USDT & STELL/TON)
│ [███]     Ecosystem & AI Dev Grants   15%     │ (150M STELL)
│ [██]      Core Team & Contributors    10%     │ (100M STELL, 12m cliff, 24m linear)
└───────────────────────────────────────────────┘
```

---

## 🚀 Quick Start Guide

### Prerequisites
* Rust 1.75+ (Cargo toolchain)
* Linux / macOS / BSD

### 1. Build and Run Tests
```bash
git clone https://github.com/immtes/stellereum.git
cd stellereum

# Run the complete test suite (999 passing, 0 failed at last full green run,
# verified on HEAD 1d595c1; the working tree may carry uncommitted wave edits)
cargo test
```

### 2. Launch Local Testnet Simulator
Experience the entire stack (3-validator BFT cluster, Masterchain + Shards, Orderbook matching, MEV preemption, zkML verification, and Cross-shard atomic routing) in-process:
```bash
cargo run -- sim --blocks 3
```

Sample output (captured from `./target/debug/stellereum sim --blocks 1`; timings
vary per run and are in-process, not the live stand):
```text
╔═══════════════════════════════════════════════════════════════╗
║      🚀 STELLEREUM LOCAL TESTNET SIMULATOR (FULL STACK)       ║
╚═══════════════════════════════════════════════════════════════╝
Initializing in-memory multi-shard cluster (Masterchain + Shards 1, 2)...
✓ Cluster initialized with 3 Validators & Quorum 2/3
✓ Genesis Accounts: Alice (7eccd1410ecd) | Bob (7f3e1d6fcecf)

--- Block #1 (Timestamp: ...) ---
  [CLOB] Alice placed Sell Order #1 | Bob placed Buy Order #2
    ↳ Matched Trade: 6000 STELL @ $0.25 USD
  [MEV] 2-of-3 Threshold Blind Round #1 Sealed & Committed (Zero Frontrunning)
  [zkML] AI Agent Inference Verified: in=[3,4] -> out=[11, 7]
  [Cross-Shard] Routed Atomic Message Shard 1 -> Shard 2 (Sequencer #1)
  [Privacy] Pedersen Confidential Transfer Verified (Homomorphic conservation fee=20)
  [Oracle] Tier 2 DEX TWAP Resolved: TON = $5.00 USD (Breaker: Clean)
  [Bridge] Teleport Gateway: Verified 2/3 Quorum for TON -> Stellereum Deposit
  ✓ Block #1 Finalized in 1.66ms (Latency < 200ms Target)
```
Note the simulator's own label: **"Quorum 2/3" is the 2-of-3 *threshold* the sim
prints, which is not the consensus finality rule.** The certificate quorum is
`floor(2*total_power/3)+1` (`ValidatorSet::quorum_power`), which for 3 unit-power
validators is **3**, not 2 (see `docs/OPERATIONS.md` §5). The simulator also
labels its own MEV line "ACTIVE" even though threshold preemption is deferred
(see Pillar 5).

---

## 💼 Wallet and CLI Commands

> **There is no separate `stell` wallet binary in this repository.** The
> `crates/stell-wallet` directory referenced by older revisions does not exist
> here; `cargo install --path .` from that path fails. Wallet support lives inside
> this crate as the `stellereum wallet` subcommand (generation, balance, address,
> send, session delegation), with the SPV/lite-client and vault logic in
> `src/wallet.rs`. The vault implementation covers BIP-39 mnemonics, Argon2id and
> XChaCha20-Poly1305, but there is no interactive REPL or orderbook/stealth
> subcommand on the CLI, and there is no `ZeroizeOnDrop`/`mlock` or POSIX file-mode
> hardening (see the security table note). Treat any external `stell` wallet as a
> separate project, not something this repo installs.

### Current command surface

```bash
# 1. Generate a keypair, viewing key and stealth address
stellereum wallet generate

# 2. Inspect an account's balance and nonce
stellereum wallet balance --address 8ef8c8e89d495a78...

# 3. Print the account address for a private key
stellereum wallet address --from-key <hex seed>

# 4. Send a standard transfer (amount in nano-STELL)
stellereum wallet send --from-key <hex seed> --to <64-hex addr> --amount 25000000000

# 5. Delegate a session key for an autonomous trading bot
stellereum wallet delegate-session --master-key <hex seed> --session-pub <hex> --max-gas 50000 --duration-secs 3600

# Orderbook / oracle / bridge / PMM operate on in-process demo objects
# rather than a running node (see docs/RPC.md §6).
stellereum orderbook depth --pair <pair>
stellereum oracle status --asset TON
```

---

## 🛡 Security Architecture & Audit Highlights

| Security Feature | Implementation Mechanism | Protection Against |
| :--- | :--- | :--- |
| **Key Derivation** | Argon2id ($m=64\text{ MB}, t=3, p=4$) | Offline GPU brute-force cracking |
| **Vault Encryption** | XChaCha20-Poly1305 with 192-bit nonce & MAC tag (24-byte nonce, `src/wallet.rs`) | Ciphertext tampering & bit-flipping |
| **MEV Protection** | Shamir Threshold Secret Sharing ($T$-of-$N$) - reconstruction only; threshold preemption is deferred (see Pillar 5) | (intended) sandwich attacks & frontrunning |
| **State Validation** | Patricia-Merkle BoC Proofs | Malicious node balance spoofing |
| **Crash Protection** | `sled` embedded ACID KV store (`src/storage.rs`) | Corrupted DB on unexpected restart |

> **Not implemented / not verified (removed from the table above):** keystore files are
> written with a plain `fs::write` and no POSIX mode is set (`save_to_file`,
> `src/wallet.rs`), so the `0600`/`0700` claim does not hold; there is no
> `ZeroizeOnDrop` or `libc::mlock` anywhere in the crate; and there is no
> "double-entry LWW / atomic tmp rename" layer - durability comes from sled.

---

## 🌐 P2P Discovery & Networking

Stellereum operates as an overlay on **infnode**:
* **DNS TXT Federation:** Seed node records are published under a configurable domain (e.g. `stellereum.org`; `testnet/node-a.yaml`); a TXT record under that domain must match the configured value.
* **Kademlia DHT / QUIC transport:** peer resolution and encrypted transport are provided by the `infnode` dependency (`infnode = { path = ... }` in `Cargo.toml`); the bucket parameters are infnode's, not defined in this crate.
* **Block storage:** finalized block bodies are serialized with bincode and stored as blobs in infnode blob storage (`src/network.rs`), addressed by hash and announced via the DHT KV. **Caveat:** there is no Reed-Solomon erasure coding or explicit 1 MB chunk constant in this crate; the infra does chunk and replicate blobs, but the "1 MB / Reed-Solomon" description does not match the code here.

---

## 📄 License

Licensed under either of:
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
* MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
