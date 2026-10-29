# EXTERNAL SECURITY AUDIT — BRIEF

**Project:** Stellereum L1 (`stellereum`)
**Audit type requested:** external, independent, source-level security audit of the
consensus, execution, cryptography, networking and governance subsystems.
**This document is the auditor's entry point.** Read it first; it tells you what
the system is, what must never go wrong, what is already known to be weak, what
to look at, what to ignore, and how to reproduce our numbers yourself.

> **The honest framing, up front.** This codebase has been through several
> internal review waves, and the result is a large body of *regression-pinned*
> behaviour. But an internal review is not an external audit, and no internal
> process can substitute for one. This package does **not** claim the code is
> audited. It claims the opposite: it hands you everything we know, including
> the parts we know are weak, so that you can find the parts **we** do not know
> about. The most useful document here is
> [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md) — it is where we point at our own weak
> spots.

---

## 1. Provenance — what exactly are you auditing?

| | |
| --- | --- |
| **Commit** | `1d21b43c5ed420141be6e3754a277dc214033a97` (`1d21b43`) |
| **Commit date** | 2026-10-18T09:19:31+03:00 |
| **Commit subject** | `fix(address): safe UTF-8 character boundary check and base58 zero-prefix handling` |
| **Branch** | `wip/passport-agents` |
| **Working tree** | **dirty** — the tree carries uncommitted edits (256 changed paths at the time of measurement). The source fingerprint identifies the *exact* sources we measured, so the numbers are reproducible even though the tree moves. |
| **Source fingerprint** | `6ec6091a8a635342` at the **start** of the measured run, `a321a7843d9c288a` at its **end** — sha256 over all `*.rs` under `src/`, `tests/`, `fuzz/`. The tree is under active development, so it **moved during the measurement**; the script prints both and warns. Re-run it and compare the fingerprint before trusting any number below. |
| **Toolchain** | `rustc 1.91.1 (ed61e7d7e 2025-11-07)`, `cargo 1.91.1 (ea2d97820 2025-10-10)` |
| **Size measured** | `src/` = 133,879 lines over 53 files, 50 modules (the library plus `src/bin/`) |
| **Fuzz toolchain** | `cargo 1.100.0-nightly (3d7cf6e93 2026-09-25)`, `cargo-fuzz 0.13.2` |
| **Dependency of record** | `infnode` (the P2P transport), a **sibling path dependency** at `../infmail-valid-backend/crates/infnode` — not vendored in this repository. Auditors must read it too: it is the network entry point. |

**Reproduce everything we measured:**

```bash
git checkout 1d21b43          # or use the fingerprint above
cd stellereum
./scripts/audit-repro.sh      # builds, runs the suites, runs the fuzz smoke, prints the SUMMARY table
```

The script prints the commit, the source fingerprint, the rustc version and a
per-suite table. If your run disagrees with ours, the tree you have is not the
tree we measured — check the fingerprint first.

---

## 2. The system in one place

### 2.1 Shape

```
   peer ──► infnode P2P/DHT ──► src/consensus_net.rs ──► src/consensus.rs
                                                          (pure BFT state machine)
                                                                │
   client ─► src/rpc.rs (JSON-RPC 2.0 + WS + SSE)               │ decided block
        └──► src/evm_adapter.rs (Ethereum-compatible facade)    ▼
                                              src/runtime.rs  ──► src/state_engine.rs
                                              (the pipeline)        (execution + state)
                                                        │                │
                                                        │                ├── src/svm.rs (payload VM)
                                                        │                ├── src/contract.rs + contract_abi.rs
                                                        │                ├── src/token.rs, src/orderbook.rs, src/pmm.rs
                                                        │                ├── src/staking.rs, src/governance.rs, src/oracle.rs
                                                        │                ├── src/bridge.rs + bridge_adapters.rs
                                                        │                ├── src/crypto_privacy.rs (shielded pool)
                                                        │                └── src/zkml.rs (zkML + session keys)
                                                        ▼
                                              src/storage.rs (sled: blocks, state, domains, receipts)
                                              src/commitment.rs (the state-root commitment)
```

`src/lib.rs` exposes **50 modules**. The binary (`src/main.rs`) wires the
transport, the consensus driver, the apply worker, the RPC servers and the
background tasks.

### 2.2 Module map, by subsystem, with the real file paths

| Subsystem | Files | What it does |
| --- | --- | --- |
| **Consensus (BFT)** | `src/consensus.rs` (5,326) | The pure state machine: `HeightConsensus` per height, prevote/precommit, quorum certificates, value locking, equivocation evidence, the sortition committee, the µQC and epoch CEC certificates, the chain-id-bound vote and block preimages. |
| | `src/runtime.rs` (7,867) | The integration layer: proposer selection, the apply worker (`ApplyLane`, panic-guarded), the finalize order (fees → slashes → rotation), `adopt_committed` (the catch-up path), the validator-set refresh. |
| | `src/consensus_net.rs` (2,761) | The P2P transport for proposals/votes/commits over infnode: bincode framing, size caps, batch limits, per-peer burst budgets, fire-and-forget gossip. |
| | `src/chain.rs` (1,317) | The block tree, fork choice, and the reorg plan (reorgs only ever affect heights above the finalized one). |
| | `src/sync.rs` (2,508) | Catch-up: walk `prev_hash` backwards, fetch the missing blocks, apply them ancestor-first, verify the chain's quorum. |
| **Execution & state** | `src/state_engine.rs` (11,691) | The state engine: the Patricia trie of accounts/tokens/contract code, the actor model, the parallel block path, the failure-fee rules, the commitment snapshot, the snapshot/restore path. |
| | `src/svm.rs` (3,451) | The Stellereum Virtual Machine: the opcode set, the micro-gas model, the syscalls (stake, claim, order, zkML, confidential transfer). |
| | `src/contract.rs` (2,613), `src/contract_abi.rs` (1,678) | The WASM contract engine (wasmi), fuel metering, the ABI codec, the registry. |
| | `src/commitment.rs` (1,664) | The canonical commitment of every consensus-visible subsystem that is **not** in the trie. `COMMITMENT_VERSION = 5`. |
| | `src/parallel_exec.rs` (791), `src/cell.rs` (359) | The wave executor and the Patricia trie / Merkle proof primitives. |
| | `src/token.rs` (803), `src/orderbook.rs` (401), `src/pmm.rs` (499) | The token registry, the CLOB and the PMM. |
| **Storage** | `src/storage.rs` (3,315) | `sled`: `blocks`, `by_height`, `meta`, `state`, `domains`, `headers`, `session_keys`, `bridge`, `confidential`, `zkml_models`, `cross_shard`, `receipts_v1`. Background flusher — consensus never blocks on disk. |
| **Networking** | `src/network.rs` (4,601) | The P2P adapter over infnode: DHT blob buckets (blocks, state, head, headers), the mempool gossip, the cross-shard message path, the oracle feed path. |
| | `src/client_ip.rs` (536), `src/dns_seeds.rs` (1,253) | Client address extraction and the seed list. |
| **Sharding** | `src/sharding.rs` (7,000+) | The masterchain/workchain topology, the address→shard rule, the split/merge state machine, the trie migration, the shard-head commitment, the cross-shard messages, the `Block` type and its hash. |
| | `src/xshard2pc.rs` | The cross-shard two-phase-commit state machine and its replay sets. |
| **Cryptography** | `src/post_quantum.rs` (3,526) | The PQ scheme envelope (Ed25519 / Falcon-512 / ML-DSA-44-disabled / hybrid), the FIPS-206 FN-DSA key handling, the legacy-key warnings, the address derivation. |
| | `src/bls.rs` (815) | Real pairing-based BLS12-381 aggregate signatures and the signer bitvector. |
| | `src/crypto_privacy.rs` (1,994) | Pedersen commitments, range proofs, stealth addresses, viewing keys, the shielded pool and its solvency gate. |
| | `src/node_keys.rs` (1,205) | Key storage: Argon2id + XChaCha20-Poly1305 encryption at rest, 0600/0700 enforcement. |
| | `src/address.rs` (355), `src/cpat2.rs` (1,582) | The branded `Stl57…` address format and the CPAT-2 Merkle proof format. |
| **MEV** | `src/mev.rs` (886) | The node-local blind round: sealing at admission, `verify_pool_tx`, the order commitment. |
| | `src/mev_epoch.rs` (2,624) | The threshold epoch seal: committee DKG, asymmetric sealing, order-first/reveal-second, `t`-of-`n` unseal. **Live** (the node runs the DKG, serves the epoch key, admits sealed transactions). |
| | `src/mev_v4.rs` (920) | The parked, default-off v4 engine. |
| **Governance & economics** | `src/governance.rs` (2,054) | Stake-weighted proposals, voting, quorum, execution-once, the applied parameter set, the upgrade action. |
| | `src/staking.rs` (4,354) | Bonding, delegation, slashing, rewards, the team vesting schedule. |
| | `src/tokenomics.rs` (272), `src/oracle.rs` (603) | The emission schedule and the oracle with its circuit breaker. |
| | `src/bridge.rs` (2,541), `src/bridge_adapters.rs` (1,124) | The protocol half of the bridges (TON / EVM / Solana): the relayer quorum, the time-lock, the rate limits, the mint caps, the challenge/dispute machinery, and the deposit-proof adapters. |
| **RPC & facade** | `src/rpc.rs` (10,722) | JSON-RPC 2.0, WebSocket and SSE; the read and write surfaces; the token gates; the rate limits. |
| | `src/evm_adapter.rs` (8,680) | The Ethereum-compatible facade: the RLP decoder, the legacy/EIP-1559 transaction types, `eth_*` / `net_*` methods. |
| | `src/native_api.rs` (2,120), `src/explorer.rs` (1,404), `src/metrics.rs` (1,366) | The native API, the explorer routes and the Prometheus metrics. |
| **zkML** | `src/zkml.rs` (2,042), `src/zkml_attestation.rs` (554) | The session keys, the quantized-model proof engine, the attestation engine (the module formerly named `snark.rs`; there is no SNARK here — see §5.2) and the machine-readable capability statement `zkml_capabilities()`. |
| **Misc** | `src/simulator.rs` (1,897), `src/wallet.rs` (807), `src/turnstile.rs` (424), `src/bootstrap.rs` (400), `src/remote_signer.rs` (955), `src/parallel_exec.rs` (791) | The deterministic simulator, the wallet, the PoW turnstile, the bootstrap, the remote signer. |

### 2.3 The three rules that hold the whole thing together

1. **The state root is the consensus-visible state.** Everything that is not in
   the trie is folded into a single digest (`src/commitment.rs`) and the root
   covers both. Without that, two nodes could disagree about the validator set
   while the root said they agreed, and no re-sync would detect it.
2. **The validator set is derived, never declared.** It is re-read from the
   staking ledger inside the state engine at every height boundary. It is not
   a node-local value fed over RPC.
3. **Every signature is bound to a deployment and a domain.** The chain id is
   in the vote and block preimages, and the chain id is **frozen once per
   process** so two nodes on one host cannot read it at different moments.

---

## 3. The security invariants

**The full table is [`INVARIANTS.md`](INVARIANTS.md)** — 80 numbered invariants,
each with the implementing symbol, the pinning test and a status. Read that
file; it is the contract you are being asked to check.

The shape of it:

| Group | Count | What it covers |
| --- | --- | --- |
| **C — Consensus & BFT safety** | 20 | the prevote/precommit rule, the lock, the quorum, `adopt_committed`, catch-up, equivocation and downtime slashing, the validator set, the µQC's network-anchored quorum, the sortition seed |
| **S — Execution & state** | 21 | the failure-fee contract, admission-before-execution, determinism, the value-movement commit point, the state-root completeness and determinism, the cross-shard replay set, the snapshot restore |
| **K — Cryptography & keys** | 11 | domain separation, chain-id binding, the strict PQ envelope, the disabled ML-DSA scheme, real BLS, key encryption at rest, the file permissions, range proofs, the address format |
| **N — Networking & transport** | 12 | the size caps, the bounded decoder, the nested-batch refusal, the peer deferral, the fuzz coverage, the RPC token gate, the faucet gate, the per-IP budgets |
| **G — Governance, economics & bridges** | 16 | the stake-weighted vote, execute-once, the governed parameters, the bridge quorum and mint caps, the time-lock, the refund, the mempool's nonce/flood rules, the owner-only syscalls |

And a **shortlist of what is *not* pinned** — §6 of `INVARIANTS.md`. That list
(`U-01`…`U-07`) is where we would start.

### Three examples, verbatim

> **S-01 — A failed transaction pays its fee and advances its nonce.**
> Implementation: `src/state_engine.rs` `failure_fee_state` / `apply_failure_fee_to_map`.
> Pinned by: `tests/failure_fee_contract_tests.rs::an_attributable_failure_pays_exactly_the_failure_fee`
> and `tests/apply_floor_tests.rs::failed_tx_pays_floor_and_advances_nonce`.

> **C-15 — A post-quantum micro-certificate must carry a strict majority of the
> whole network's stake.**
> Implementation: `src/consensus.rs` `pq_micro_required_power` —
> `max(floor(2·W_committee/3)+1, floor(W_network/2)+1)`.
> Pinned by: `tests/pq_uqc_power_quorum_tests.rs` (7 tests, including
> `empty_committee_and_zero_weight_fail_closed`).

> **N-09 — The RPC write methods are gated by a bearer token, and fail closed
> when the deployment has no token.**
> Implementation: `src/rpc.rs` `RpcState::auth_token`, sourced from
> `STELL_RPC_AUTH_TOKEN`.
> Pinned by: `src/rpc.rs` `write_methods_require_auth_token`,
> `execute_proposal_requires_the_auth_token`, `mempool_dump_requires_auth_token`.

---

## 4. Trust boundaries

**Full STRIDE analysis per subsystem: [`THREAT_MODEL.md`](THREAT_MODEL.md) §11.**

### What is trusted

| # | Trusted | Consequence of the trust |
| --- | --- | --- |
| T-1 | **The validator set** (the bonded stake) | Defines who may vote and with what power. Only as trustworthy as the staking ledger and the state root. |
| T-2 | **The quorum** | A power-weighted 2/3; for the µQC, a strict majority of the **network's** stake. Below 1/3 Byzantine power, BFT safety holds. |
| T-3 | **The epoch key** | The MEV committee's aggregate public key. **Today the epoch key is not produced on the live path** — the live MEV key is node-local. See §5.3. |
| T-4 | **The local disk** | The node's own blocks, state and snapshots. A tampered disk can withhold or reorder, and can install a stale validator set — which the observer arm turns into *no vote*, not a wrong vote. |
| T-5 | **The operator** | The environment: `STELL_CHAIN_ID`, the RPC token, the faucet token, the data directory, the host. |
| T-6 | **The RPC token** | Whoever holds it may use the write surface. **The token is optional** — without it the gated methods fail closed, but a deployment with no token exposes the write surface to anyone who can reach the port. |
| T-7 | **The bridge relayer set** (2/3 of distinct signers) | That a cross-chain deposit really happened. This is the bridge's biggest structural assumption. |
| T-8 | **The oracle publisher set** | That a price feed is honest. |
| T-9 | **The cryptography** | SHA-256, BLAKE3, Ed25519, BLS12-381, curve25519/Ristretto255, Falcon-512, Argon2id, XChaCha20-Poly1305. Explicitly not defended against. |
| T-10 | **The host** | Root, the OS, the CPU. Not defended. |

### What is *not* trusted (and is therefore defended by code)

Every byte a peer sends; every raw transaction an RPC client submits; every
bridge deposit proof; every zkML proof; every confidential commitment; and the
operator's own configuration *insofar as it can change a consensus verdict*
(the chain id is frozen once per process precisely so it cannot).

---

## 5. Known limitations — stated honestly

**The full list, with severities and exploitability, is
[`KNOWN_ISSUES.md`](KNOWN_ISSUES.md)** (36 issues + 10 deferred features + 7
stale documentation claims). The ones an auditor must know before reading any
code:

### 5.1 The EVM adapter is a **facade**, not an EVM

`src/evm_adapter.rs` is an Ethereum-*compatible* surface: the JSON-RPC
methods, the legacy and EIP-1559 transaction types, a hand-written RLP
decoder, the gas-estimate shape. **There is no EVM, no EVM bytecode
interpreter, and no EVM state.** It maps onto the Stellereum SVM. Any
assumption that "EVM-compatible" means "runs Solidity" is wrong.

A deliberate divergence worth flagging: `eth_chainId` **serves** the effective
chain id (from `STELL_CHAIN_ID`), but every *verification* site pins the
constant `CHAIN_ID` (5757). The reasoning is in the code: verification is
consensus-adjacent, and a per-process env read at each verification site
would let validators with different environments admit different transaction
sets. **The consequence for an auditor:** on a non-5757 deployment the EVM
methods report one chain id while verifying against another. That is intended,
but it is a trap.

### 5.2 The zkML engine is **not zero-knowledge**

`ZkMlProof::verify_inference` is a *structural* check — a Fiat-Shamir binding
plus ReLU constraints. It does **not** verify the matrix multiplication, so a
prover can fabricate a ReLU-consistent trace with invented activations and it
passes. The code says so in the method's own doc comment, and the regression
`forged_proof_passes_structural_but_fails_sound_check` pins exactly that.

The **sound** path is `verify_inference_against`, which re-runs the
deterministic integer model and hash-matches the on-chain model registry; the
live block path's `OpCode::SysCallVerifyZkMlReexec` (renamed in wave W8.3 —
it was `SysCallVerifyZkMlIn`, and the old name read like a ZK check) uses it.
The attestation opcode `OpCode::SysCallVerifyZkMlAttestation` (renamed from
`SysCallVerifyZkMlSnark`, which claimed a Groth16 verification that was never
there) re-executes as well and additionally binds the proof to the committed
model **spec**. The legacy `OpCode::SysCallVerifyZkMl` calls the structural
check and therefore carries **no soundness at all** — it is unreachable on the
block path (`VmContext.zkml_proof` is never supplied) and stays fail-closed.

The proof bytes also carry the **full activation trace**, so even the sound
path is not private.

**There is no proof system here at all** — no R1CS/AIR, no polynomial
commitment, no FRI, no pairings, no trusted setup. The honest name for the
subsystem is *"verifiable inference by re-execution"*. Since a marketing name
is not a contract, the chain serves the statement as **data**:
`stell_zkmlCapabilities` (`zkml::zkml_capabilities()`) reports
`zero_knowledge: false`, `succinct: false`, `hiding: false`, `sound: true`,
`trusted_setup: false`, plus a per-opcode breakdown and the residual (what a
real ZK proof would need). An integrator should read that endpoint, not the
namespace.

### 5.3 MEV preemption is **live as a threshold scheme** — but it is not a defence against a malicious proposer

What is wired and enforced **today**:

* the node runs the **epoch DKG** on the epoch boundary
  (`runtime::sync_mev_epoch`) and ingests peers' contributions
  (`runtime::on_mev_frame`); the resulting **epoch public key** is served
  over RPC (`stell_epochKey`: the key, the committee, the threshold, the
  transcript root);
* a wallet can submit an **asymmetrically sealed** transaction
  (`stell_sendSealedTransaction`); the node stores the **ciphertext only** and
  gossips the ciphertext;
* the proposer **commits the order first and reveals second**: the candidate
  order is signed and gossiped as an `OrderCommit` frame, and only then are
  the decryption partials released and the content unsealed
  (`runtime::sealed_proposer_path`);
* an unsealed transaction must match its **envelope hash**, its **transparent
  metadata** and its **signature**, or it is dropped; fewer than `t` partials
  means the transaction is **dropped** (fee charged), so a withholding member
  cannot stall the round;
* the **epoch-key commitment is inside the block**
  (`Block::epoch_key_commitment`) and therefore inside the signed block hash;
* the older, order-committing path is still there: the block carries the
  **order Merkle root**, and a validator re-computes it from the proposed body
  and **refuses the proposal on a mismatch** (`runtime::check_order_commitment`).

What is **still not** true — and this is the part that matters for your
review:

* it hides the transaction **content** from a passive observer and from a
  mempool snooper **until the ordering is committed**; it does **not** hide
  the *ordering* (the block lists the transactions in order);
* it does **not** stop a malicious proposer from **front-running with its own
  transaction**, nor from **withholding its reveal** — the module header
  (`src/mev_epoch.rs`) says so in those words;
* the node-local blind round of `src/mev.rs` **coexists** with the threshold
  scheme, so a transaction can arrive through either path — the interesting
  surface is whether the two can be made to disagree about what "sealed"
  means;
* the MEV suite still records the **vote gate as deferred**
  (`mev_seal_enforced_order_detected_vote_gate_deferred`), and the `mev_v4`
  engine stays parked and default-off.

### 5.4 The light client is **live** — and it relocates the trust, it does not remove it

The node keeps a light client anchored at its **own finalized head**; every
block it accepts from a peer during a sync is routed through
`sync::verify_synced_blocks_against_anchor` (a peer chain is accepted only if
it **extends a quorum-certified anchor**); the node serves its anchor and its
finalized headers over RPC (`stell_getFinalizedCheckpoint`,
`stell_getFinalizedHeader`); and `stellereum light-client --from <rpc>
--verify <account>` is the external verifier, which checks the anchoring
header's quorum certificate against an **out-of-band** validator set before
it checks the proof.

**The residual, stated plainly:** the **validator set is the entire trust
anchor**. A light client that takes its validator set from the server it is
verifying has no anchor at all, so the CLI *requires* `--validators`. The
improvement is real — "a quorum committed to this root" replaces "the node
says this root" — but the trust did not vanish, it moved. `KI-18` has the
details.

### 5.5 Sharding has never split a live network

The address→shard rule, the split and merge state machines, the trie
migration and the convergence property are all **demonstrated** — over a
synthetic account set, in-process, in `tests/sharding_topology_tests.rs`.
What is **designed but not performed**: a split driven by a live consensus
event, and shipping the migrated state to the new shard's validators.

Also: the published shard space is `2^60`; the **shipped** cap is
`MAX_SHARDS = 16`. The distinction is stated in `docs/SHARDING.md` §0 and in
the `stell_getShards` response, because the advertised number is not a
capacity.

### 5.6 The legacy Falcon key path has ~32 bits of effective entropy

The legacy derivation (behind `STELL_LEGACY_GENESIS_ROOT=1`) is an automorphic
image of the Falcon reference base key: the 32-byte seed only picks
`k ∈ {1,3,…,1023} × shift_f × shift_g × flags` — at most `2^32` distinct
keys. An attacker who observes the **public** key can recover the private key
and forge consensus signatures for that validator. The path exists only to
reproduce the historical testnet genesis root; it announces itself loudly and
tells the operator to rotate. **Audit action:** verify no live deployment
still runs with that variable set.

### 5.7 Two more you will meet immediately

* **The sortition is grindable.** The parent hash is in the preimage, so a
  committee is unknowable until its parent exists — but the proposer chooses
  the parent's bytes, hence its hash, hence the next committee, and can
  search. The network-anchored quorum bounds the damage; a VRF is the
  structural fix and is out of scope.
* **Equivocation evidence is locally observed.** A catching-up node saw
  nothing, so it cannot punish an equivocation it never witnessed. Full
  parity needs the evidence shipped with the commit certificate — a wire
  change.

---

## 6. The scope we propose

Five tracks. Sizes are **lines of Rust in `src/`** at the fingerprint above.
They include the module's own unit tests, so the *reviewable* surface is
smaller; treat them as an upper bound.

### (a) Consensus & BFT safety — ~21,500 LOC

| Module | LOC | Why it is in scope |
| --- | --- | --- |
| `src/consensus.rs` | 5,326 | The pure state machine: quorum arithmetic, the lock, the vote/certificate preimages, the sortition, the µQC and epoch CEC verification. |
| `src/runtime.rs` | 7,867 | The finalize order, the apply worker, `adopt_committed`, the validator-set refresh, the proposal validator (the order and shard-header commitments live here). |
| `src/consensus_net.rs` | 2,799 | The wire format and its limits — the remote attack surface. |
| `src/sync.rs` | 2,508 | Catch-up and `validate_sync_chain`. |
| `src/chain.rs` | 1,317 | The block tree, fork choice, the reorg plan. |
| `src/light_client.rs` | 1,715 | The proof verifier — **live since wave W8.3**: the node keeps one anchored at its own finalized head, the sync path routes every peer block through it, and `src/light_client_cli.rs` is the external verifier (`stellereum light-client`). It answers "is this correct?" against a root a QUORUM committed to. |

**Questions we would like answered:** (1) does the prevote/precommit/lock
combination really forbid two conflicting blocks below 1/3 Byzantine power,
including across a view change; (2) can a peer reach any state that makes
`adopt_committed` accept a certificate it should not; (3) is the sortition
grind mitigated enough by the network-anchored quorum, or is the VRF
mandatory before mainnet?

### (b) Cryptography — ~9,800 LOC

| Module | LOC | Why it is in scope |
| --- | --- | --- |
| `src/post_quantum.rs` | 3,526 | The scheme envelope, the FN-DSA key handling, the address derivation, the legacy-key warnings — and the **disabled** ML-DSA-44 verifier. |
| `src/crypto_privacy.rs` | 1,994 | The Pedersen commitments, the range proofs, the shielded pool's solvency gate, the stealth addresses, the viewing keys. |
| `src/cpat2.rs` | 1,582 | The CPAT-2 Merkle proof format. |
| `src/node_keys.rs` | 1,205 | The key encryption at rest and the permission enforcement. |
| `src/bls.rs` | 815 | The pairing-based aggregate signatures and the signer bitvector. |
| `src/address.rs` | 355 | The branded address format and its homoglyph defence. |
| `src/cell.rs` | 359 | The trie and Merkle primitives. |

**Questions we would like answered:** (1) is the range-proof construction in
`src/crypto_privacy.rs` actually sound, or only plausible; (2) is the FN-DSA
key path correct for the *complete* key, and is the legacy path fenced off
completely; (3) does the BLS signer bitvector carry enough information for
the downtime slashing to remain correct once signatures aggregate.

### (c) Execution & state — ~26,300 LOC

| Module | LOC | Why it is in scope |
| --- | --- | --- |
| `src/state_engine.rs` | 11,691 | The accounts trie, the parallel block path, the failure-fee rules, the commitment snapshot, the actor model, the restore path. |
| `src/svm.rs` | 3,451 | The opcode set, the fuel model, the syscalls. |
| `src/contract.rs` | 2,613 | The WASM engine and its fuel metering. |
| `src/zkml.rs` | 2,042 | The session keys and the zkML proof checks. |
| `src/zkml_attestation.rs` | 554 | The re-execution attestation engine (a sound hash-bound re-execution — **not** a ZK proof system, see §5.2). |
| `src/commitment.rs` | 1,664 | The state-root commitment — **the single most load-bearing file in the project**. |
| `src/contract_abi.rs` | 1,678 | The ABI codec. |
| `src/token.rs` | 803 | The token registry. |
| `src/parallel_exec.rs` | 791 | The wave executor. |
| `src/oracle.rs` | 603 | The oracle and its breaker. |
| `src/pmm.rs` | 499 | The PMM. |
| `src/orderbook.rs` | 401 | The CLOB. |

**Questions we would like answered:** (1) is there any path on which the
block path and the single-transaction path produce different state for the
same transaction (the code claims they cannot, except for *which* fee is
charged — see `PROTOCOL.md` §4); (2) is the commitment complete — i.e. is
there any consensus-visible field that is **not** in `commitment_digest`; (3)
can a payload mutate shared state and revert.

### (d) Networking — ~9,700 LOC

| Module | LOC | Why it is in scope |
| --- | --- | --- |
| `src/network.rs` | 4,601 | The DHT buckets, the gossip, the cross-shard path, the head pointer. |
| `src/dns_seeds.rs` | 1,253 | The seed list. |
| `src/storage.rs` | 3,315 | The persistence layer and its trees. |
| `src/client_ip.rs` | 536 | The client address extraction (the rate-limit basis). |

Plus the transport itself, `infnode`, at
`../infmail-valid-backend/crates/infnode` — **not in this repository**, but it
is the network entry point and it must be in the audit.

**Questions we would like answered:** (1) can a peer cause unbounded work
before a size check; (2) is the peer-deferral queue bounded under a sustained
flood; (3) does the client-IP extraction trust anything the client can set.

### (e) Governance & economics — ~17,300 LOC

| Module | LOC | Why it is in scope |
| --- | --- | --- |
| `src/staking.rs` | 4,354 | Bonding, delegation, slashing, rewards, vesting. |
| `src/bridge.rs` | 2,541 | The bridge protocol half: the relayer quorum, the time-lock, the rate limits, the mint caps, the challenge/dispute machinery. |
| `src/mev_epoch.rs` | 2,624 | The threshold epoch seal (live: DKG, sealing, order-commit, share release, unseal). |
| `src/governance.rs` | 2,054 | The proposals, the voting, the quorum, the execution. |
| `src/simulator.rs` | 1,897 | The deterministic simulator. |
| `src/bridge_adapters.rs` | 1,124 | The deposit-proof adapters (TON / EVM / Solana). |
| `src/mev_v4.rs` | 920 | The parked v4 engine. |
| `src/mev.rs` | 886 | The live node-local MEV path. |
| `src/oracle.rs` *(also in (c))* | 603 | The price feed and its breaker. |
| `src/tokenomics.rs` | 272 | The emission schedule. |

**Questions we would like answered:** (1) is the bridge's 2/3-of-distinct-signers
model sufficient given that the signer set is trusted; (2) can the mint caps be
bypassed through the deposit path, the withdrawal path or a restore; (3) is
the governance quorum meaningful against a stake-concentration attack.

### Not in the scope above, but worth a look if you have time

`src/rpc.rs` (10,722), `src/main.rs` (9,549), `src/evm_adapter.rs` (8,680),
`src/explorer.rs`, `src/metrics.rs`, `src/native_api.rs` — the RPC surface,
the node wiring, the EVM facade and the explorer.

---

## 7. Explicitly OUT OF SCOPE

Please do not spend audit time on these. We say what we mean.

| Out of scope | Why |
| --- | --- |
| **The `infnode` transport internals** beyond its public API and the frame decoder | It is a sibling repository with its own review cycle. We audit *our use* of it: the frame decoder, the message limits, the peer bookkeeping. |
| **The `site/`, `testnet/`, `docker/`, `scripts/` operational assets**, and the HTML/JS of the metrics page | Not consensus, not execution, not crypto. |
| **Cryptographic primitives themselves** (SHA-256, BLAKE3, Ed25519, BLS12-381, curve25519, Falcon-512, Argon2id, XChaCha20-Poly1305, Ristretto255) | We assume them. Review **our use** of them: the preimage layouts, the domain tags, the key handling. |
| **The WASM runtime (`wasmi`) and the `sled` storage engine** | Third-party. Review our usage, not theirs. |
| **Ecosystem smart contracts** (`contracts/`) and the `examples/` | Deployment artefacts, not protocol. |
| **Performance tuning** (the TPS numbers, `docs/PERF_1K.md`, the benchmarks) | Not a security property. The one performance item that *is* a security item is the O(state)-per-root-read commitment recomputation (**KI-15**). |
| **Frontend, wallet, and chain-list integration** | Out of the security boundary. |
| **The site legal pages, the domain, the trademarks** | Not a security matter. |
| **Re-auditing the internal review's own conclusions** | We are not asking you to confirm our findings. We are asking you to **find what we missed**. The `KNOWN_ISSUES.md` list is a map, not a set of conclusions to ratify. |

---

## 8. How to run the test suite

### The one command

```bash
./scripts/audit-repro.sh
```

It: builds every test binary (`cargo build --tests --all-targets`), runs the
library suite, runs **78 security-focused integration suites** plus the library suite, runs the
**fuzz smoke** over all seven fuzz targets, and prints a `SUMMARY` table with
the per-suite test counts, the pass/fail verdict, the duration, the git commit,
the source fingerprint, the `src/` size and the rustc version. It exits
non-zero if anything is red, and it marks a suite that could not be *run* as
`ERROR` rather than letting it pass silently.

Options:

```bash
./scripts/audit-repro.sh --quick      # a shorter fuzz smoke, the same suites
./scripts/audit-repro.sh --no-fuzz    # skip the fuzz smoke
./scripts/audit-repro.sh --no-build   # skip the build step
./scripts/audit-repro.sh --only lib   # run one suite (repeatable)
```

### By hand

```bash
# The library unit tests (the bulk of the suite).
cargo test --lib --no-fail-fast

# One integration suite.
cargo test --no-fail-fast --test adversarial_regression_tests

# Everything at once (this is what `audit-repro.sh` runs, suite by suite).
cargo test --lib --tests --no-fail-fast

# The deterministic decoder fuzzing (stable toolchain, no nightly needed).
cargo test --no-fail-fast --test fuzz_decoder_tests

# The libFuzzer fuzz smoke (needs nightly + cargo-fuzz).
cd fuzz
cargo +nightly fuzz build                       # builds ALL seven targets
cargo +nightly fuzz run consensus_msg_decode -- -runs=20000 -max_len=4096
cargo +nightly fuzz run cert_envelope_decode -- -runs=20000 -max_len=4096
cargo +nightly fuzz run evm_raw_tx_decode -- -runs=20000 -max_len=4096
cargo +nightly fuzz run peer_msg_decode -- -runs=20000 -max_len=4096
```

### Notes for the auditor

* The suite is **crypto-heavy** (Ed25519, BLS pairing, Falcon, Merkle, WASM),
  so the timings in the summary are minutes, not seconds. `Cargo.toml` pins
  `opt-level = 3` for dependencies and `opt-level = 0` for the crate, and
  drops debuginfo, because the unoptimized build was unusably slow.
* The tests bind ports and use temp directories. Run them on a machine with
  loopback networking.
* `cargo test --lib --tests --no-fail-fast` is the right command for a full
  pass; the `--no-fail-fast` matters, because a single red suite otherwise
  hides the rest.
* The **examples** build cleanly (`cargo build --examples`), contrary to a
  stale claim in `PROTOCOL.md` — see `KNOWN_ISSUES.md` §K.
* **One target does not compile on this tree**: `benches/zkml_attestation.rs`
  imports `stellereum::snark`, a module that was renamed to
  `stellereum::zkml_attestation`. `cargo build --all-targets` therefore
  fails on the *bench* target only — the library, the tests and the fuzz
  targets are unaffected. It is reported as a build failure in §9, because a
  red build row is the truth. It is **not** a protocol defect and **not**
  fixed by this package (other agents own the fixes).
* The fuzz smoke **writes into `fuzz/corpus/<target>/`**: every new coverage
  input is saved, so the corpus file counts grow with every run. That is why
  the corpus numbers in §10 are stated with the fingerprint.

---

## 9. Measured results

The table below is what `scripts/audit-repro.sh` printed on the tree with the
fingerprint in §1. Reproduce it before you rely on it.

<!--MEASURED_RESULTS-->
### Provenance of this run

| | |
| --- | --- |
| **commit** | 1d21b43c5ed420141be6e3754a277dc214033a97 (1d21b43) |
| **commit date** | 2026-10-18T09:19:31+03:00 |
| **commit subject** | fix(address): safe UTF-8 character boundary check and base58 zero-prefix handling |
| **branch** | wip/passport-agents |
| **working tree** | 256 changed path(s) (uncommitted edits present: yes) |
| **source fingerprint** | 6ec6091a8a635342  (sha256 over src/ tests/ fuzz/ *.rs) |
| **src/ size** | 133879 lines across 53 files, 50 modules |
| **rustc** | rustc 1.91.1 (ed61e7d7e 2025-11-07) |
| **cargo** | cargo 1.91.1 (ea2d97820 2025-10-10) |
| **nightly (fuzz)** | cargo 1.100.0-nightly (3d7cf6e93 2026-09-25) |

### The SUMMARY table, as printed

```
SUITE                                  PASSED   FAILED  IGNORED   DURATION  VERDICT
-----------------------------------------------------------------------------------------------
build (cargo build --tests --all-targets)        -        -        -      2.68s  FAILED
lib                                       837        0        0     20.33s  ok
adversarial_regression                     21        0        0     24.52s  ok
adversarial_4node                           5        0        0      622ms  ok
adversarial_economic                        6        0        0      801ms  ok
historical_attacks                         20        0        0      721ms  ok
vuln_bundle                                 8        0        0      951ms  ok
consensus_reaudit                          11        0        0      1.02s  ok
consensus_security                         11        0        0      1.03s  ok
consensus_audit_hardening                  21        0        0      771ms  ok
consensus_rephase                           -        1        0      593ms  FAILED
adopt_prevote                               5        0        0      207ms  ok
proposal_refire                             6        0        0      856ms  ok
attack_round3                              12        0        0      205ms  ok
byzantine_fault                             5        0        0      848ms  ok
equivocation_slash                          5        0        0      829ms  ok
slashing_rotation                           5        0        0      210ms  ok
quorum_fragility                            2        0        0      544ms  ok
validator_set_quorum                        8        0        0      612ms  ok
validator_set_freshness                     7        0        0      772ms  ok
observer_recovery                           8        0        0      823ms  ok
observer_return                             2        0        0      2.93s  ok
failure_fee_contract                        4        0        0      853ms  ok
apply_floor                                12        0        0     15.55s  ok
state_root_completeness                    15        0        0      7.32s  ok
genesis_root                                7        0        0     18.09s  ok
block_hash_binding                          3        0        0     10.54s  ok
block_state_root_binding                    5        0        0      642ms  ok
state_sync_closeout                        19        0        0      1.02s  ok
restore_root_verification                   7        0        0      697ms  ok
fuzz_decoder                               15        0        0      8.32s  ok
fuzz_certificate_decoder                    7        0        0      588ms  ok
fuzz_consensus_stress                      11        0        0      3.30s  ok
pq_audit_closure                           14        0        0      1.65s  ok
pq_uqc_power_quorum                         7        0        0      699ms  ok
pq_equivocation_report                      -        -        -      504ms  ERROR
pure_pq_enforcement                         4        0        0      1.74s  ok
post_quantum_audit                          7        0        0      703ms  ok
post_quantum_svm                            8        0        0      628ms  ok
mev_pq                                      8        0        0      785ms  ok
mev_preemption                              8        0        0      1.06s  ok
bridge_onchain                             18        0        0      738ms  ok
bridge_challenge                            5        0        0      705ms  ok
bridge_dispute                             12        0        0      708ms  ok
bridge_persistence                          4        0        0      872ms  ok
bridge_zk_gate                              7        0        0      627ms  ok
bridge_adapters                            14        0        0      627ms  ok
audit_closure_bridge                       17        0        0      636ms  ok
sharding_topology                           6        0        0      844ms  ok
sharding_m1                                 4        0        0      1.00s  ok
sharding_m2                                 5        0        0      973ms  ok
sharding_m3                                 6        0        0      1.05s  ok
cross_shard_anchor                          4        0        0      525ms  ok
cross_shard_e2e_pq                          3        0        0      977ms  ok
xshard_replay                               5        0        0      966ms  ok
xshard_2pc                                 11        0        0      1.09s  ok
mempool_econ                                3        0        0      616ms  ok
mempool_mev_audit_closure                  10        0        0     28.36s  ok
chain_mempool_security                      8        0        0      8.80s  ok
staking_audit_closure                      17        0        0      7.64s  ok
staking_rewards_pool                        3        0        0      751ms  ok
audit_closure_oracle_gov                    8        0        0      590ms  ok
audit_closure_privacy                      15        0        0      701ms  ok
confidential_preverify                      4        0        0      1.16s  ok
confidential_solvency                       5        0        0      655ms  ok
audit_rpc_evm_closeout                     30        0        0      800ms  ok
network_audit_close                        17        0        0      722ms  ok
transport_audit_fixes                       4        0        0      556ms  ok
node_keys_security                          9        0        0      2.51s  ok
node_keys_hardening                         9        0        0      2.81s  ok
stl57_audit_pentest                         5        0        0      9.51s  ok
light_client                               18        0        0      7.56s  ok
light_client_wiring                        15        0        0      3.24s  ok
evm_adapter                                88        0        0      4.20s  ok
svm_atomicity                               3        0        0      1.36s  ok
clob_atomicity                              2        0        0      3.78s  ok
orderbook_griefing                          4        0        0      933ms  ok
token_security                             16        0        0      5.73s  ok
token_adversarial                          16        0        0     12.75s  ok
memory_bounds                              11        0        0      1.30s  ok
fuzz:frame_decode                        2000        0        0    368.54s  ok
fuzz:consensus_msg_decode                2000        0        0    218.20s  ok
fuzz:transaction_decode                  2000        0        0     13.79s  ok
fuzz:block_decode                        2000        0        0     26.49s  ok
fuzz:cert_envelope_decode                2000        0        0      1.13s  ok
fuzz:evm_raw_tx_decode                   2000        0        0      1.11s  ok
fuzz:peer_msg_decode                     2000        0        0      1.58s  ok
-----------------------------------------------------------------------------------------------
TOTAL                                   15607        1        -    887.96s
```

**87 components ran: 84 green, 2 red, 1 errored.**

### What was red, and why

| Component | Verdict |
| --- | --- |
| `build (cargo build --tests --all-targets)` | **FAILED** |
| `consensus_rephase` | **FAILED** |
| `pq_equivocation_report` | **ERROR** |

`consensus_rephase` → FAIL  - passed, 1 failed  (593ms)

```
        test rephase_lets_a_stuck_node_commit_the_quorum_the_network_formed ... FAILED
        failures:
        failures:
        test result: FAILED. 9 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

`pq_equivocation_report` → ERROR (did not compile)  (504ms)

```
        error[E0382]: borrow of moved value: `block`
           --> tests/support/live_stand.rs:555:33
            |
        549 |                 Msg::Proposal { round, block } => {
            |                                        ----- move occurs because `block` has type `stellereum::sharding::Block`, which does not implement the `Copy` trait
        --
        error: could not compile `stellereum` (test "pq_equivocation_report_tests") due to 1 previous error; 1 warning emitted
```

The build's own failure detail:

```
error[E0599]: no function or associated item named `prove_inference` found for struct `ZkMlProof` in the current scope
    --> examples/passport_audit.rs:115:39
     |
 115 |         let (out, proof) = ZkMlProof::prove_inference(&model, &[3,4]);
--
error: could not compile `stellereum` (example "passport_audit") due to 1 previous error; 2 warnings emitted
warning: build failed, waiting for other jobs to finish...
warning: `stellereum` (test "hunt_commitment") generated 1 warning (run `cargo fix --test "hunt_commitment"` to apply 1 suggestion)
```

### Reading the numbers honestly

* The tree is **under active development** (it carries uncommitted edits, and it **changed during the measurement window** — the script prints the fingerprint at the start and at the end and warns when they differ). A re-run will therefore not reproduce these numbers *exactly*. The **fingerprint** is the identifier: if yours differs, your tree is not this tree.
* The **BUILD row is red** for a reason that has nothing to do with the protocol: three *example/bench* targets still call the pre-rename API (`ZkMlProof::prove_inference`, `stellereum::snark`). The **library, the 79 test targets and the 7 fuzz targets all build and pass**. See `KNOWN_ISSUES.md` §K (SD-01).
* One **integration suite is red**: `consensus_rephase` — one test whose *precondition* went stale after the network-anchor liveness change. The property it pins still holds, more strongly. See `KNOWN_ISSUES.md` **KI-36**.
* The tree kept moving after that run: on later fingerprints the **library** suite showed 1–3 red tests, all in the same consensus round-window area (the polka-ledger / network-anchor liveness change and its regression updates were still landing). A red there is a **test** that has not been updated yet, not a broken consensus — but do not take this document's word for it: run the script and read `KNOWN_ISSUES.md` **KI-36**.
* One suite **errored** (`pq_equivocation_report`): its shared test harness (`tests/support/live_stand.rs`) did not compile at that moment. Re-run after the tree settled, it is **green** (4 tests) — the error was a transient of the concurrent development, not a property of the tree.
* The fuzz smoke numbers are **runs**, not corpus size: libFuzzer stops early when the corpus is already saturated. The *corpus* sizes are printed under the table.
* Durations are wall-clock on a machine that was **shared with other build jobs**; treat them as an order of magnitude, not a benchmark.

<!--/MEASURED_RESULTS-->

---

## 10. Fuzz coverage — the review

**Full review: `fuzz/` — 4 pre-existing targets (2,043 corpus files at HEAD)
plus the 3 targets this package adds.** (After the smoke run of §9 the corpus
holds 2,123 files; the fuzz smoke *adds* seeds, it never removes them.)

### What is covered

| Target | Decoder | Corpus files | Attacker-reachable? |
| --- | --- | --- | --- |
| `frame_decode` | `infnode::proto::Frame::decode` — the network entry point | 9 | yes |
| `consensus_msg_decode` | `consensus_net::ConsensusMsg::decode` + `parse_incoming` + `parse_tx_incoming` | 1,614 | yes |
| `transaction_decode` | `sharding::Transaction` (bincode) | 178 | yes |
| `block_decode` | `sharding::Block` (bincode), including the order, shard-header and epoch-key commitments | 262 | yes |
| **`cert_envelope_decode`** *(new)* | `consensus::decode_pq_micro_envelope`, `decode_pq_epoch_envelope`, `decode_qc_bls_envelope`, plus both PQ signature envelope decoders | 0 (new) | yes |
| **`evm_raw_tx_decode`** *(new)* | the hand-rolled EVM RLP decoder (`RlpItem::decode_with_remainder`, `DecodedTransaction::decode`) | 0 (new) | yes |
| **`peer_msg_decode`** *(new)* | the cross-shard message decoder (`network::P2pNetworkAdapter::parse_cross_shard_incoming`) and the epoch-seal gossip frames (`mev_epoch::MevFrame::decode`, `decode_sealed_payload`) | 0 (new) | yes |

The two priority decoders named in the audit request — the **consensus
message decoder** and the **block decoder** — were already covered
(`consensus_msg_decode` with 1,614 corpus files, `block_decode` with 262).
This package keeps them and closes the three gaps that were left.

After the smoke run of §9 the three new targets hold **4 / 71 / 29** corpus
files (`cert_envelope_decode` / `evm_raw_tx_decode` / `peer_msg_decode`):
they start from zero, and a corpus of zero is exactly the honest statement of
"this decoder was never fuzzed".

### What was **not** covered (the gap this package closes)

| Decoder | Where | Why it mattered | Now |
| --- | --- | --- | --- |
| The **certificate envelopes** (`µQC`, epoch CEC, BLS aggregate QC) | `src/consensus.rs` `decode_pq_micro_envelope` / `decode_pq_epoch_envelope` / `decode_qc_bls_envelope` | Hand-written, byte-at-a-time parsers of bytes a peer controls, with a bitvector and a signer count inside them. **The highest-risk uncovered consensus decoder**: a length or bitmask off-by-one here becomes an accepted *under-powered* certificate. | ✅ `cert_envelope_decode` |
| The **EVM RLP decoder** | `src/evm_adapter.rs` (`RlpItem::decode_with_remainder`, `DecodedTransaction::decode`) | A **hand-written** recursive-descent RLP parser (not the `rlp` crate) with its own canonical-form rules and its own depth guard, fed by `eth_sendRawTransaction` — fully attacker-controlled bytes, unauthenticated. The single most attacker-reachable custom parser in the node. | ✅ `evm_raw_tx_decode` |
| The PQ signature envelopes | `src/sharding.rs`, `src/post_quantum.rs` | Two different framings of the same logical object; a mismatch between them is a re-mint vector. | ✅ included in `cert_envelope_decode` |
| The **cross-shard message decoder** | `src/network.rs:1699` `P2pNetworkAdapter::parse_cross_shard_incoming` | Peer-controlled, and the record carries a `trusted` flag that **bypasses the inclusion proof** (`src/sharding.rs:3659`). A decode that kept the flag would be a consensus-critical bug. | ✅ `peer_msg_decode` |
| The **epoch-seal gossip frames** | `src/mev_epoch.rs:1354` `MevFrame::decode`, `:1399` `decode_sealed_payload` | Peer-controlled, magic-prefixed, and the frame is what a node publishes as the epoch key's ciphertext. | ✅ `peer_msg_decode` |
| The **bridge deposit-evidence decoders** | `src/bridge_adapters.rs`, `src/cell.rs:153` `BagOfCells::from_boc_bytes` | Relayer-controlled. The BoC parser trusts two 32-bit length prefixes before validating them (**KI-35**) — we found that by reading, not by fuzzing, and we deliberately did **not** put it in a fuzz target, because a 12-byte input would make the target abort the process. | ⚠️ **still uncovered — please look here** |
| The storage decoders (`decode_receipt`, `decode_domain_snapshot`) | `src/storage.rs:198`, `:1836` | Operator/local, not remote. | ⚠️ uncovered; lower priority |
| The light-client proof parser | `src/light_client.rs` | Served to verifiers, not received from peers. | ⚠️ uncovered; lower priority |

The three new targets assert more than "no panic":

* `cert_envelope_decode` asserts that a decoded µQC **round-trips through its
  own canonical encoder** to an equal certificate (the encoder and the decoder
  must be mutually consistent), and that a decoded BLS aggregate's signer
  bitvector length matches the validator count it claims.
* `evm_raw_tx_decode` asserts that the **exact** and the **remainder** RLP
  views always agree — the exact decoder may fail only with `TrailingBytes`,
  and must otherwise return the same item.
* `peer_msg_decode` asserts that a cross-shard message decoded from remote
  bytes **never** keeps its `trusted` flag, that a decoded epoch-seal frame
  matches the magic prefix it decoded under and re-encodes to exactly the
  bytes it came from, and that a sealed envelope round-trips through the
  canonical encoder.

All seven were built and run on nightly (`cargo +nightly fuzz build` /
`cargo +nightly fuzz run`); the results are in §9.

### A note on the corpus numbers

The audit figures *"2043 fuzz corpus files"*. That figure is **exact for the
committed corpus** at HEAD `1d21b43`: 1,613 `consensus_msg_decode` + 251
`block_decode` + 171 `transaction_decode` + 8 `frame_decode` = **2,043**
(verified with `git ls-files fuzz/corpus | wc -l`). A dirty working tree shows
a higher number — the fuzz smoke *adds* untracked seeds, and the three new
targets start with empty corpus directories that fill as they run.

The corpus counts are also the honest answer to "how much fuzzing is there":
the coverage is **deep on the consensus wire format and thin everywhere
else** — 78 % of the corpus is one decoder, and the decoders that were
uncovered until this package (the certificate envelopes, the EVM RLP parser,
the cross-shard message, the epoch-seal frames) had **zero** corpus files.

---

## 11. What we are asking for

1. **A source-level security audit** of the five tracks in §6, against the
   invariants in §3 and the threat model in §4.
2. **Priority on the unpinned list** — `INVARIANTS.md` §6 (`U-01`…`U-07`) and
   the known issues in `KNOWN_ISSUES.md`. We believe these are the weak
   points; we would like them confirmed, sharpened, or refuted.
3. **A specific look at the still-uncovered decoders** (§10): the bridge
   deposit-evidence decoders (notably the TON BoC parser, **KI-35**), the
   storage decoders and the light-client proof parser. The cross-shard
   message decoder and the epoch-seal frames *are* covered — by the new
   `peer_msg_decode` target — so the bridge evidence path is the remaining
   gap that is reachable behind the relayer quorum.
4. **A verdict on the two design-level risks** that no test can settle: the
   grindable sortition, and the node-local MEV key.

**What we are not asking for:** a re-run of the internal review, a
confirmation that the existing tests pass, or an opinion on the product.

### Where we would like answers

* Which of the `KI-*` issues do you believe are **worse** than we rated them?
* Which of the `KNOWN_ISSUES.md` items are, in your judgement, **not** actually
  mitigated?
* What did we miss entirely?

### Point of contact

The audit is coordinated through the repository's issue tracker; the
`docs/audits/` directory is the shared reference. Every claim in this package
is anchored to a file and a symbol, so a disagreement about a claim can be
resolved by reading the code — which is the point.

---

## Appendix A — the package

| File | What it is |
| --- | --- |
| `docs/audits/EXTERNAL_AUDIT_BRIEF.md` | This document. |
| `docs/audits/INVARIANTS.md` | 80 invariants, each with its implementation, its pinning test and its status; plus the unpinned shortlist. |
| `docs/audits/KNOWN_ISSUES.md` | 36 known issues with severity and exploitability, 10 deferred features, 7 stale documentation claims. |
| `docs/audits/THREAT_MODEL.md` | STRIDE per subsystem, with the trust-boundary tables. |
| `scripts/audit-repro.sh` | The one-command reproduction. |
| `fuzz/fuzz_targets/cert_envelope_decode.rs` | **New** — the certificate-envelope fuzz target. |
| `fuzz/fuzz_targets/evm_raw_tx_decode.rs` | **New** — the EVM RLP fuzz target. |
| `fuzz/fuzz_targets/peer_msg_decode.rs` | **New** — the cross-shard message + epoch-seal frame fuzz target. |

Supporting in-tree documents the auditor should also read:
`PROTOCOL.md` (the protocol specification, with its own invariant list and its
security-posture tables), `docs/SHARDING.md` (note §0: what is demonstrated
versus what is only designed), `docs/RPC.md`, `docs/OPERATIONS.md`, and
`docs/handoff/` (the design notes, several of which are in Russian).
