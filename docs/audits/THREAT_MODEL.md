# THREAT MODEL (STRIDE, per subsystem)

> **Scope.** The node as it runs: the consensus engine, the execution and state
> engine, the P2P transport, the RPC surface, the key material, the storage
> engine, the MEV path, governance, the bridges, the sharding layer and the
> privacy layer.
>
> **Attacker model.** Three classes, with different reach:
>
> | Class | Reach | Assumed capability |
> | --- | --- | --- |
> | **E1 — remote peer** | the P2P transport and the RPC port | can send arbitrary bytes, arbitrary message counts, arbitrary sizes; cannot forge a signature; cannot read the node's disk |
> | **E2 — validator** | the P2P transport **plus** a share of stake | as E1, plus the ability to sign blocks/votes and to equivocate |
> | **E3 — operator** | the node's disk, the environment, the process | as E2, plus the ability to misconfigure, to read the data directory, to run local code |
>
> **Out of the attacker model** (i.e. *assumed*, not defended): a fully
> compromised host with root, a malicious CPU/hardware supply chain, a
> break of SHA-256/BLAKE3/Ed25519/BLS12-381/Falcon-512/curve25519, and a
> 51%-of-stake coalition (which can censor and reorg but cannot break
> BFT safety below 1/3 Byzantine power).
>
> **Legend.** `Mitigation` names the code that implements it, with the symbol;
> `Residual` names what is left. The invariant IDs refer to
> [`INVARIANTS.md`](INVARIANTS.md); the issue IDs refer to
> [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md).
>
> **Spot-check 2026-10-30 (AUDITPREP).** Five mitigations were re-verified
> against the current tree and all five still hold as written: the order
> commitment (`runtime.rs:4623` `check_order_commitment`, `mev.rs:384`), the
> failure-fee contract (`state_engine.rs:937`), the burst-deferral queue
> (`consensus_net.rs:1888` test pin; `INBOUND_DEFERRED_CAP = 1024` now lives
> in `src/main.rs:1134`), the disabled scheme `0x03` (`post_quantum.rs:159`
> / `:181` / `:2367`), and the BoC length-prefix shape (`cell.rs:165`,
> `:176` `with_capacity` before validation — KI-35 stays open). No stale row
> was found among the five.

---

## 1. Consensus & BFT (`src/consensus.rs`, `src/consensus_net.rs`, `src/runtime.rs`)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S**poofing | A peer claims to be a validator and injects votes under someone else's key. | Every vote is signed and verified on ingestion; the signer id is inside the signed preimage (`vote_sign_bytes`, domain `STELLEREUM_BFT_VOTE_V2`), so a vote cannot be re-labelled. Chain-id binding stops cross-deployment replay (**C-01**). | None known. |
| **S**poofing | A peer injects a **proposal** signed by someone else. | `validate_proposal_unaligned` checks the declared proposer against the signature and the round schedule; `adopt_committed` refuses a certificate that does not name the scheduled proposer (**C-07**, **C-18**). | None known. |
| **T**ampering | A proposer reorders a block after the votes, or swaps a transaction. | The **order Merkle root** is inside the signed block hash; every validator re-computes it from the proposed body and refuses a mismatch (`runtime::check_order_commitment`, `mev::compute_order_merkle_root`). The **shard-head commitment** is likewise inside the block hash. | The order check is a hard rule that every validator must run before it votes — a **coordinated rollout** requirement. The *vote* gate for MEV sealing is deferred (**KI-34**, **U-01**). |
| **T**ampering | A peer forges a quorum certificate. | Certificates are verified against the **local** validator set with power weighting (`ValidatorSet::quorum_power`); an empty set fails closed with `u64::MAX` (**C-06**). The µQC path additionally demands a strict majority of the **network's** stake (**C-15**). | The quorum is over *this node's* set; a node with a stale set fails closed to observer (**C-14**). |
| **R**epudiation | A validator equivocates (signs two conflicting votes) and denies it. | Equivocation evidence is recorded as a signed pair, deduplicated by the pair, and consumed by `apply_equivocation_slashes`, which burns real stake from the pool (**C-10**, **C-12**). | Evidence is **locally observed**: a catching-up node saw nothing (**KI-08**). Ship the evidence with the commit certificate. |
| **R**epudiation | A validator is punished for being partitioned rather than for misbehaving. | Downtime is derived from the **quorum certificate** of a finalized block, not from a local timer, and is replay-idempotent per height (**C-11**). | A validator that misses many blocks still loses a bounded amount (0.1% burn after 10 consecutive misses, 100-height cooldown). |
| **I**nformation disclosure | A peer learns which transactions are pending before the block is built. | Transactions are sealed in the mempool under a round key; the block build re-opens the envelope and requires an exact byte match (`mev::verify_pool_tx`). | The round key is **node-local**, so the proposer itself sees the plaintext (**KI-34**). |
| **D**enial of service | A peer floods rounds to wedge the pair (a "round DoS"). | A peer message advances the round by at most one; rounds move on the node's own timeout (**C-05**). | None known. |
| **D**enial of service | A peer sends a huge or malformed consensus message. | Size caps before decode (`MAX_CONSENSUS_MSG` 32 MiB, `MAX_TX_MSG` 1 MiB), a bounded bincode (`with_limit`), a nested-batch refusal, per-peer burst budgets with **deferral** instead of dropping, and a fuzz corpus over the decoders (**N-01**…**N-06**). | The bincode **trailing-byte** acceptance means one logical message has several byte forms (**KI-11**); the µQC decoder has a second (non-canonical) parse path (**KI-10**). |
| **D**enial of service | A peer drives the node into O(state) work per root read. | — | The commitment is recomputed per root read (**KI-15**). |
| **E**levation of privilege | A peer gets a proposal accepted that it should not, or takes over the proposer slot. | The proposer slot is derived from the round schedule; the certificate must name it (**C-18**); `adopt_committed` additionally refuses a prevote-kind certificate, a wrong height/round and a fabricated state root (**C-07**). | None known. |
| **E**levation of privilege | A peer influences the validator set (captures the next set). | The set is re-derived from the staking ledger in the state engine at every height boundary, never fed over RPC (**C-13**). | The **sortition** is grindable: a proposer can search for a favourable committee (**KI-07**, **U-04**). The network-anchored quorum bounds the damage. |

---

## 2. Execution & state (`src/state_engine.rs`, `src/svm.rs`, `src/commitment.rs`)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S**poofing | A transaction signed by someone else is executed. | `Transaction::verify_signature` binds the sender, the nonce, the amount, the gas and the payload into the signed message; admission verifies before the payload runs (**S-07**). | The **legacy** PQ envelope had several accepted layouts; it is now strict — exactly one valid byte form (**K-02**). |
| **T**ampering | A failed transaction is free and replayable (the classic "free failure" griefing vector). | The F-01 failure fee: an attributable failure pays `max(gas_limit, consensus floor) + surcharge` **and advances the nonce** (**S-01**). | None for the covered cases. The floor is a **consensus** floor, read by both admission and the proposal validator, so they cannot drift (**S-06**). |
| **T**ampering | A failure the sender cannot afford is used to burn the sender's dust. | The **no-pay, no-state-change** rule: an uncoverable failure moves *nothing* (**S-02**). A replay or a nonce gap is not attributable (**S-03**). | None known. |
| **T**ampering | A payload mutates shared state and then reverts, leaving a partial effect. | Clone-commit execution; payloads run sequentially in block order (**S-08**). | None known. |
| **T**ampering | Two nodes disagree about the state while the root says they agree (an invisible fork). | `commitment_digest` folds every consensus-visible subsystem into the root; the digest is deterministic (sorted maps) and is written on read (**S-12**…**S-14**). | The digest is one blob, not per-key, so per-entry archive proofs are not possible (**KI-16**). |
| **R**epudiation | A node claims it applied a block it did not. | The block carries its precommit QC; sync verifies the QC instead of trusting bare signatures; the finalized `(height, hash)` is recorded. | — |
| **I**nformation disclosure | A node leaks another account's balance through the state root. | The trie commits `balance ‖ nonce` leaves; the root is a hash. | The RPC exposes the balances it is asked to; there is no per-address authorisation on the read path (by design for a public chain). |
| **D**enial of service | A transaction burns the node's CPU (a payload that loops). | Fuel metering in the SVM and in the contract engine; `GET_METHOD_SAFETY_FUEL_LIMIT` for reads; `stell_estimateFee` has its own budget and a 5,000,000-gas ceiling. | A payload that is *legitimately* expensive still costs the network; the floor makes it non-free (**S-06**). |
| **D**enial of service | A worker panics on a deterministic block and wedges the node forever. | The apply worker is wrapped in `catch_unwind` (`runtime.rs` uses `FutureExt::catch_unwind`), with a loud park. | None known — but a panic-freedom proof would be stronger than the guard. |
| **E**levation of privilege | A stranger forces a victim's unbond, rotates its key, or cancels its order. | Every such syscall is **owner-only**; the whole set is replayed literally in `tests/adversarial_regression_tests.rs` (**G-16**). | None known. |
| **E**levation of privilege | A transaction executes its payload even though admission failed. | Admission is checked before payload execution (**S-07**). | None known. |

---

## 3. Networking (`src/network.rs`, `src/consensus_net.rs`, `src/client_ip.rs`)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S**poofing | A peer spoofs its source address to escape a rate limit. | `src/client_ip.rs` derives the client address from the transport's own metadata, not from a client-supplied header. | A proxy in front of the node that forwards a spoofable `X-Forwarded-For` defeats this — the deployment must not trust that header. |
| **T**ampering | A peer replays a valid message. | Messages are bound to their height/round/hash; certificates are bound to the height and round they name; the replay set and the bridge source-tx set are committed (**G-07**). | bincode trailing bytes give one logical message several byte forms (**KI-11**) — a byte-derived replay filter would be unsound. |
| **R**epudiation | A peer denies having sent a message. | — | There is no signed peer transcript. Vote signatures provide partial accountability for *votes*, not for transport. |
| **I**nformation disclosure | A peer observes pending transactions before they are ordered. | The **threshold epoch seal** hides the content until the order is committed: the proposer commits the order first (`OrderCommit`), the committee releases the decryption partials second, and only then is the content unsealed (`runtime::sealed_proposer_path`); the sealed-payload wire format is `src/mev_epoch.rs`. | It does **not** hide the *ordering* (the block lists the transactions in order) and it does **not** stop a proposer front-running with its **own** transaction (**KI-34**). The older node-local blind round (`src/mev.rs`) coexists with the threshold scheme. |
| **D**enial of service | A peer floods the node with messages. | Per-peer burst budgets with **deferral** (not dropping), bounded inbound queues (`INBOUND_DEFERRED_CAP` = 1024), size caps before decode, and a bounded consensus gossip outbox. | A **distributed** flood is not bounded by the per-peer budget. |
| **D**enial of service | A peer sends a frame that makes the decoder panic. | The infnode `Frame::decode` is fuzzed and pinned never to panic (**N-05**); the same for the consensus, block, transaction, certificate-envelope and EVM-RLP decoders (**N-06**). | The **certificate-envelope**, **EVM-RLP**, **cross-shard** and **epoch-seal** decoders had **no** coverage before this package — they are the three new fuzz targets (`cert_envelope_decode`, `evm_raw_tx_decode`, `peer_msg_decode`). |
| **E**levation of privilege | A peer reaches the RPC write surface. | The write methods are gated by `STELL_RPC_AUTH_TOKEN`; when the token is not configured the gated methods **fail closed** (**N-09**). | The token is **optional** — a deployment with no token exposes the write surface to anyone who can reach the port (**KI-19**). |

---

## 4. Storage (`src/storage.rs`, `src/sync.rs`, `src/chain.rs`)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **T**ampering | The operator (or a thief with the disk) edits the data directory to rewrite history. | Blocks are content-addressed by their hash; the chain is verified by `validate_sync_chain` against the validator quorum (**C-09**); the state root is checked on restore. | The **local disk** is a trust boundary: a node with a writable data directory can withhold blocks and feed a doctored peer a fork, but cannot forge a quorum-signed chain. |
| **R**epudiation | — | The finalized height/hash are persisted and the commit certificate is stored with the block. | — |
| **D**enial of service | A corrupt snapshot or a truncated blob wedges the node. | Undecodable domain snapshots are a loud `Err` that never touch the validator set; a corrupt faucet record fails closed to empty. | — |
| **E**levation of privilege | A restored snapshot installs a **stale** validator set and the node votes on it. | The restore path compares the snapshot height with the state height and fails closed to **observer** (**C-14**); `refresh_validator_set_from_staking_checked` takes real heights. | A restore where both heights agree but the content is old still yields a stale-but-consistent set; the observer arm is the backstop. |
| **D**enial of service | A far-behind node cannot catch up. | The head pointer is a replicated DHT blob; headers are published every block; the retro-publish pass republishes bodies. | Bodies are published on a **best-effort** cadence; a node deeper than the window cannot catch up from that peer (**KI-21**). |
| **T**ampering | A peer feeds the node a fork during catch-up. | Every block accepted from a peer is routed through `sync::verify_synced_blocks_against_anchor`: a peer chain is accepted only if it **extends a quorum-certified anchor** (the node's own finalized header with its precommit QC). The light client is **live** and the tripwire test `light_client_is_wired_into_the_sync_path` fails if the node ever stops depending on it. | The anchor is the node's own finalized head, so the node can still be steered onto *a* chain that extends it but is not the canonical one; and the **validator set remains the entire trust anchor** for an external verifier (**KI-18**). |
| **S**poofing | An external verifier trusts a root the server merely asserted. | The node serves its **finalized anchor** and its finalized headers over RPC (`stell_getFinalizedCheckpoint`, `stell_getFinalizedHeader`), and the CLI verifier (`stellereum light-client`) checks the anchoring header's quorum certificate against an **out-of-band** validator set before it checks the proof. | A verifier that takes the validator set from the server has no anchor at all — the CLI **requires** `--validators`; the residual is the quorum's own honesty (**KI-18**). |

---

## 5. Cryptography & keys (`src/post_quantum.rs`, `src/bls.rs`, `src/crypto_privacy.rs`, `src/node_keys.rs`, `src/address.rs`)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S**poofing | An attacker poses as a validator by forging its signature. | Ed25519 for votes, real BLS12-381 pairing for the aggregate certificate, Falcon-512 (FIPS 206) for the post-quantum path; scheme `0x03` is refused fail-closed (**K-03**). | The **legacy** Falcon derivation has ~32 bits of effective entropy — a key made that way is recoverable from its public key (**KI-02**). |
| **T**ampering | A signature is verified over different bytes than it was produced over (domain confusion). | Every preimage has a domain tag and a length-delimited layout: votes (`STELLEREUM_BFT_VOTE_V2`), blocks (`STELLEREUM_BLOCK_V3`), sortition (`STELL_SORTITION_V5`), the oracle, the commitment domains, the PQ envelopes, the epoch seal. The chain id is in the vote and block preimages (**C-01**, **C-02**). | None known. |
| **R**epudiation | A validator claims it never signed. | Signatures are per-object and the equivocation evidence is a signed pair, recorded and deduplicated (**C-10**). | Evidence must be **observed** to be usable (**KI-08**). |
| **I**nformation disclosure | The node's private key leaks through a log, an error message or a serialization. | The Falcon private half is **not** `pub` (`src/post_quantum.rs`); the key is encrypted at rest by default (Argon2id + XChaCha20-Poly1305) and the passphrase comes from the environment, never from a file (**K-06**). | An existing **plaintext** key still loads until a passphrase is available (**KI-20**). |
| **D**enial of service | A peer makes the node burn CPU in a pairing check or a lattice verify. | The BLS path is off by default; the verifier is behind the same size caps as everything else. | A µQC with a large committee costs a batch verify per peer message. |
| **E**levation of privilege | An attacker uses a disabled scheme to bypass signature verification. | `PqScheme::from_id(3)` refuses; `verify_pq_signature` returns `false`; every byte-driven admission path refuses at parse time (**K-03**). | The variant is retained so every `match` stays exhaustive — a future re-enable must be a coordinated hard fork (**KI-01**). |

---

## 6. MEV (`src/mev.rs`, `src/mev_epoch.rs`, `src/mempool.rs`)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **T**ampering | A proposer reorders a block after the votes. | The order Merkle root is inside the signed block hash and is re-computed and enforced by every validator; the epoch-key commitment is inside the block too. | The *content* half is now live (the threshold epoch seal), but a malicious proposer can still **withhold its reveal** or **front-run with its own transaction** (**KI-34**). |
| **T**ampering | A node mutates a pooled transaction between admission and build. | `mev::verify_pool_tx` requires an exact byte match against the sealed envelope; `mev::commit_block_order` / `verify_block_order` record and check the node-local commitment. | The node-local map is an **optimisation and extra evidence**; the consensus check is the authority. |
| **I**nformation disclosure | The proposer reads the plaintext of pending transactions. | The **threshold epoch seal** hides the content until the order is committed: the proposer commits the order first, the committee releases the decryption partials second, and only then is the content unsealed (`runtime::sealed_proposer_path`). | It does **not** hide the *ordering* (the block lists the transactions in order) and it does **not** stop a proposer front-running with its **own** transaction (**KI-34**). The older node-local blind round (`src/mev.rs`) is still in the path. |
| **E**levation of privilege | A submitter decrypts another submitter's transaction. | The threshold scheme is order-first / reveal-second with `t`-of-`n` partials (`src/mev_epoch.rs`); an unsealed transaction must match its envelope hash, its transparent metadata and its signature, or it is dropped. | A member that withholds its share cannot stall the round (fewer than `t` partials ⇒ the transaction is **dropped**, fee charged) — but a malicious proposer can still front-run with its **own** transaction (**KI-34**). |
| **D**enial of service | A proposer withholds the reveal, stalling the round. | The live path fails closed: fewer than `t` partials **drop** the sealed transaction with its fee charged, never a stall. | Only the sealed path is covered; a transaction that arrives through the coexisting node-local blind round (`src/mev.rs`) follows that path's rules — the seam between the two is the surface to review (**KI-34**). |

---

## 7. Governance & economics (`src/governance.rs`, `src/staking.rs`, `src/oracle.rs`, `src/pmm.rs`)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S**poofing | A staker votes with weight they do not have, or votes twice. | Weight is snapshotted from the staking ledger at vote time; one vote per voter per proposal; votes are locked and cannot be changed (**G-01**, **G-02**). | — |
| **T**ampering | A proposal is applied twice, or a parameter that governs the chain is decorative. | Execution is idempotently guarded (**G-03**); governed parameters are actually read (`AppliedParams`, `VmContext`) (**G-05**). | — |
| **E**levation of privilege | A minority captures governance by inflating its weight. | The quorum is `GOVERNANCE_QUORUM_BPS` = 6,666 with a 3,333 floor, over stake-weighted power (**G-04**). | Governance actions have **no timelock** (**KI-23**). |
| **T**ampering | An oracle publisher moves the price to extract value. | The same publisher key may move an asset at most 5% per feed; a >10% single step latches the global circuit breaker (3-day governance reset). | The shipped rule is a deviation cap, not a median or a TWAP (**KI-25**). |
| **D**enial of service | A delegation flood or a stake-grab. | Per-account limits, the unbonding cooldown, the delegation-leg cap on the slash. | — |
| **R**epudiation | A validator claims it was slashed unfairly. | Slashes are driven by block evidence (the quorum certificate), never by a local observation (**C-11**). | — |

---

## 8. Bridges (`src/bridge.rs`, `src/bridge_adapters.rs`)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **S**poofing | A single relayer fakes a quorum. | The threshold counts **DISTINCT** signers (2/3) and fails closed on an empty set (**G-07**). | The signer set is a **trusted** set (see §11) — this is the bridge's largest structural risk (**KI-26**). |
| **T**ampering | A deposit proof is forged or replayed. | Evidence is **verified** (TON BoC hashes, EVM MPT proofs, SHA-256 Merkle proofs) and the source-tx hash is a committed replay set (**G-07**, **G-12**). | Replay-set persistence is committed, so a restart does not reopen the protection (**G-11**). |
| **E**levation of privilege | A quorum mints without limit. | An hourly rate limit and a **cumulative** mint cap that live in **committed state** (**G-08**). | A restored pre-F-H V1 state starts the counters at zero (**KI-29**). |
| **D**enial of service | A dispute stalls the withdrawal queue. | Bounded deferrals (`MAX_RESOLVE_DEFERRALS`), a challenge age cap, a dispute reward. | The challenge machinery needs **off-chain watchers** to be useful (**KI-27**). |
| **D**enial of service | A crafted TON BoC blob makes the node attempt a 500 GiB allocation. | The blob is size-capped (64 KiB) and the BoC is parsed only **after** the header quorum and the depth checks. | The BoC's two 32-bit length prefixes reach `with_capacity` **before** they are validated (**KI-35**): a hard abort on a host where the allocation fails, reachable only behind a 2/3 signer quorum. |
| **I**nformation disclosure | A relayer learns the withdrawer's identity before the time-lock expires. | The withdrawal is parked in the escrow and the time-lock applies above 50,000 STELL (**G-09**). | The `stell_recipient` is in the parked record; the bridge state is committed, so it is chain-visible. |
| **R**epudiation | A relayer denies a release. | The release carries the relayer signatures; the dispute window and the challenge bond exist. | — |

---

## 9. Sharding (`src/sharding.rs`, `src/xshard2pc.rs`)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **T**ampering | A node routes a transaction to the wrong shard. | **One** rule, one source of truth (`sharding::route_shard`): longest-prefix match on the address's leading bits, ties broken by the smallest shard id; the masterchain is addressed explicitly (`-1:`). | — |
| **T**ampering | A cross-shard message is applied twice. | The consumed-message set, the produced-outbound log and the completed-lifecycle set are committed (**S-18**). | The commitment is **per-process**, not per-shard (**KI-17**). |
| **T**ampering | A masterchain block commits to a shard head that contradicts the node's own finalized header. | The commitment must not contradict the node's own finalized headers. | The **contradiction case** is not pinned by a named test (**U-03**); the canonical-set rule is only partly pinned (**U-02**). |
| **E**levation of privilege | A node claims shards it does not host. | Shard routing is a pure function of the topology. | A **live** split has never been performed and the cross-node migration is not implemented (**KI-30**). |

---

## 10. Privacy (`src/crypto_privacy.rs`, `src/zkml.rs`)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| **I**nformation disclosure | The amount of a shielded transfer leaks. | Pedersen commitments with positional **range proofs** on every input and every output; fail-closed, no equation-only fallback (**K-09**). | — |
| **S**poofing | A negative balance is minted (the "infinite mint" the audit flagged). | Range proofs bound every commitment to `[0, 2^64)`; the first-spender-wins rule and the ownership map close the double-spend and the theft paths (**K-09**, **K-10**). | A direct caller of the **bare** `apply_transfer` bypasses the range check (**KI-06**). |
| **I**nformation disclosure | The sender of a shielded transfer is identified. | Stealth addresses for the recipient. | The **sender is always public** (`tx.from` + nonce + public gas); there is no RingCT and no anonymity (**KI-05**). |
| **T**ampering | A zkML proof is fabricated to trigger a value-bearing decision. | The sound path re-runs the deterministic integer model and hash-matches the on-chain model (`verify_inference_against`); the live opcodes are `SysCallVerifyZkMlReexec` and `SysCallVerifyZkMlAttestation`, and both use the sound path. | The structural check `verify_inference` is **not sound** and the legacy opcode `SysCallVerifyZkMl` uses it — it is unreachable on the block path (`VmContext.zkml_proof` is never supplied) (**KI-31**). |
| **I**nformation disclosure | The model, the inputs or the outputs of an "zk" inference leak. | Nothing hides them: the proof carries the public inputs and outputs in the clear, and the verifier holds the whole model. | The subsystem is **sound but not zero-knowledge and not succinct**; `zkml::zkml_capabilities()` says so in machine-readable form (**KI-31**, **KI-33**). |

---

## 11. Trust boundaries — what is trusted, and what is not

This is the list an auditor should hold in their head. **Everything not on
the trusted list must be defended by code; everything on it must be stated
plainly in the deployment runbook.**

### Trusted (by design)

| # | Trusted thing | What trusting it means | Where it is enforced |
| --- | --- | --- | --- |
| T-1 | **The validator set** (the bonded stake) | The set defines who may vote and with what power. It is *derived from the staking ledger*, so it is only as trustworthy as the ledger and the state root. | `src/runtime.rs` `refresh_validator_set_from_staking`; `src/staking.rs` |
| T-2 | **The quorum** (a power-weighted 2/3, and for the µQC a strict majority of the **network's** stake) | That a quorum certificate is honest. Below 1/3 Byzantine power, BFT safety holds. | `src/consensus.rs` `quorum_power`, `pq_micro_required_power` |
| T-3 | **The epoch key** (the MEV committee's aggregate public key) | That the sealed-transaction key is known only to the committee. The epoch key **is** produced on the live path now (the DKG runs, the key is served as `stell_epochKey`, and its commitment is inside the signed block hash). The *node-local* blind-round key of `src/mev.rs` coexists with it. | `src/mev_epoch.rs`; `src/runtime.rs:2129` `sync_mev_epoch`; `src/rpc.rs:3499` `stell_epochKey`; `src/sharding.rs:4297` `Block::epoch_key_commitment`; `src/mev.rs` (the node-local layer) |
| T-4 | **The local disk** (the data directory) | That the node's own persisted blocks, state and snapshots are what they claim. A tampered disk can withhold or reorder, and can make the node vote on a stale set (which the observer arm converts into *no vote*, not a wrong vote). | `src/storage.rs`; `src/node_keys.rs` (0600/0700, encrypted keys) |
| T-5 | **The operator** (the environment, the config, the passphrase, the process) | That `STELL_CHAIN_ID`, `STELL_RPC_AUTH_TOKEN`, `STELL_FAUCET_TOKEN`, the data directory and the host are what the operator believes. | `src/main.rs`; `docs/OPERATIONS.md` |
| T-6 | **The RPC token** (`STELL_RPC_AUTH_TOKEN`) | That whoever holds the token may use the write surface. The token is optional; without it the gated methods fail closed. | `src/rpc.rs` `RpcState::auth_token` |
| T-7 | **The bridge relayer set** (2/3 of distinct signers) | That a cross-chain deposit really happened. This is the bridge's biggest structural trust assumption. | `src/bridge.rs` `quorum_threshold` |
| T-8 | **The oracle publisher set** (governance-approved keys) | That a price feed is honest. | `src/oracle.rs`; `src/governance.rs` |
| T-9 | **The cryptography** (SHA-256, BLAKE3, Ed25519, BLS12-381, curve25519/Ristretto255, Falcon-512, Argon2id, XChaCha20-Poly1305, Ristretto255-based Shamir) | That the primitives hold. Explicitly *not* defended against. | — |
| T-10 | **The host** (root, the OS, the CPU) | Not defended. | — |

### NOT trusted (and therefore defended by code)

| # | Untrusted input | Where it is rejected |
| --- | --- | --- |
| N-1 | Every byte a peer sends | `src/consensus_net.rs` (size caps, bounded bincode, nested-batch refusal), `src/network.rs`, the fuzz corpus (**N-01**…**N-06**) |
| N-2 | Every raw transaction an RPC client submits | `src/evm_adapter.rs` (strict RLP, canonical-form checks, depth limit), `src/mempool.rs` (admission), `src/state_engine.rs` (execution) |
| N-3 | Every proof attached to a bridge deposit | `src/bridge_adapters.rs` (**G-12**) |
| N-4 | Every zkML proof | `src/zkml.rs` `verify_inference_against` (**KI-31**) |
| N-5 | Every confidential commitment | `src/crypto_privacy.rs` (range proofs, ownership, spent set) (**K-09**, **K-10**) |
| N-6 | The **operator's** own configuration, insofar as it can change the *consensus* verdict | The chain id is **frozen once per process** (`FROZEN_CHAIN_ID`), so two nodes on one host cannot read it at different moments and derive different vote preimages. The EVM adapter's *served* id follows the environment but its *verification* pin is a constant, so a per-process env read at each verification site cannot let validators admit different transaction sets. |

---

## 12. What the model does **not** cover

* **Economic attacks** that are rational but not malicious (a validator that
  earns more by censoring than by voting) — out of scope for a code audit.
* **The 51% coalition**: it can censor and reorg; it cannot break BFT safety
  below 1/3 Byzantine power.
* **Availability of the foreign chains** a bridge depends on: a reorg deeper
  than the confirmation depth, or a 51% attack on the foreign chain, is not
  curable by any bridge — only by confirmation depth.
* **The host**: root, the OS, the hardware, a malicious supply chain.
* **Social engineering of the operator**: the passphrase, the token, the
  deployment.
* **The bridge's foreign-chain security**: the deposit adapters verify
  *inclusion* against a header the relayer set quorum-attests; they do not
  verify the foreign chain's own consensus (**KI-26**). A foreign chain that
  reorgs inside the confirmation depth is a bridge problem, not a node bug.
* **The economics of the MEV scheme**: whether the threshold epoch seal is
  *worth* its latency is a market question. This model only covers whether it
  does what the code says it does (**KI-34**).
* **The light client's own trust anchor**: the model says what the code
  checks; it cannot say whether the quorum that finalized the anchor was
  honest (**KI-18**).

---

## 13. Where the auditor's time should go

Derived from the model, not from a wish list. Each line points at a
document in this package.

| # | Target | Why | Where |
| --- | --- | --- | --- |
| 1 | The **BFT safety core** under a view change | The lock, the polka and the precommit-QC interaction are where a fork would live. | `src/consensus.rs`, `src/runtime.rs`; invariants C-01…C-19 |
| 2 | The **commitment completeness** | If a consensus-visible field is not in the digest, two nodes can disagree while the root says they agree — an invisible fork. | `src/commitment.rs`; invariant S-12; U-05, U-06 |
| 3 | The **unpinned list** | Seven properties the code enforces but no test would fail on if they broke. | `INVARIANTS.md` §6 |
| 4 | The **known-issues list**, severity by severity | Especially **KI-35** (the BoC length prefixes) and **KI-11** (trailing bytes defeat byte-derived replay filters). | `KNOWN_ISSUES.md` |
| 5 | The **unfuzzed decoders** | The bridge evidence decoders and the storage decoders are still uncovered; the BoC one is a *known* amplifier, not a suspected one. | brief §10; `fuzz/` |
| 6 | The **MEV transition** | The node-local blind round and the threshold epoch seal coexist; the seam between them is where a downgrade would live. | `src/mev.rs`, `src/mev_epoch.rs`; KI-34 |
