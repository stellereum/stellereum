---
title: Threat model
description: A STRIDE-style threat model across network, consensus, state, wallet, faucet, governance, upgrade and bridge.
outline: deep
---

# Threat model

This is a working threat model, not a security proof. It describes what the
system tries to defend, against whom, with which mechanism, and what remains.

::: danger Testnet
No external audit. Several “mitigations” below are policy or monitoring, not
cryptographic guarantees. Treat the residual-risk column as the relevant one.
:::

## Actors and trust boundaries

| Actor | Capability | Cannot |
| --- | --- | --- |
| **E1 — remote peer** | send arbitrary bytes to P2P and RPC; open connections; submit signed transactions | forge a signature, read disk, bypass admission, vote |
| **E2 — validator** | E1 + stake; sign votes/proposals, equivocate, choose transaction order, front-run with its own tx | unilaterally finalize below quorum, rewrite finalized history |
| **E3 — operator** | disk, env, local code, keys, service manager | change consensus rules without the binary/genesis |
| **E4 — user / wallet** | hold a key, sign messages and transactions | exceed the key's authority or the grant's scope |
| **E5 — sponsor / session master** | delegate fee or scoped authority | move the delegate's value beyond the grant |

Trust boundaries:

```text
wallet key  ──sign──▶  transaction bytes  ──P2P/RPC──▶  mempool
                                                   │
                                                   ▼
                                          block proposal / votes
                                                   │
                                                   ▼
                                          state engine + trie
                                                   │
                                                   ▼
                                          snapshots / proofs / indexer
```

The validator **distrusts peers** (verifies signatures, QCs, roots, shard
heads, 2PC proofs), **distrusts its own timers for punishment** (slashes only on
block evidence), and **distrusts operator memory** (a genesis fingerprint
refuses to start on a changed chain).

## Assets

1. **Consensus safety** — no two conflicting finalized blocks.
2. **Liveness** — the chain keeps finalizing.
3. **Funds** — native balances, token balances, bridge escrow, staking pools.
4. **Identity** — validator keys, node identity, EVM bindings.
5. **Availability** — RPC, indexer, explorer, faucet.
6. **User intent** — the transaction the user actually authorized.
7. **Upgrade integrity** — the bytes that run are the bytes governance approved.

## STRIDE legend

| Letter | Threat | Question |
| --- | --- | --- |
| **S** | Spoofing | can an actor claim another identity? |
| **T** | Tampering | can bytes/state be modified? |
| **R** | Repudiation | can an action be denied? |
| **I** | Information disclosure | can secrets or intent leak? |
| **D** | Denial of service | can the system be stalled or exhausted? |
| **E** | Elevation of privilege | can an actor exceed its authority? |

## Network (P2P transport)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Peer claims another node id | node id = `blake3(ed25519 pubkey)[..20]`; peer stanzas pin `ed-pub` / `pq-pub` | a misconfigured admin can admit the wrong stanza |
| S | Transport identity swap | `pq_id = blake3("infnode-pqid-v1" ‖ falcon_pk)[..20]`; peers pin it | a new `pq-identity.key` requires editing every peer's config |
| T | Frame tampering / replay | PQ handshake, exact `FRAME_VERSION = 2`, hybrid KEX on verified PQ, per-frame authenticated encryption | classical fallback is removed; no mixed mode |
| T | Cross-chain replay | chain id in block hash and vote preimage; epoch/topic derived from genesis root | a chain-id-only reset keeps the same topic and relies on hash separation |
| R | Message origin denial | consensus votes carry the validator id and signature; evidence is in blocks | proposal-equivocation evidence locally observed (KI-08) |
| I | Traffic analysis | payload encryption; sealed transactions hide content from the pool | metadata (sender, nonce, gas, shards) is public |
| D | Connection flood / slow peer | bounded queues, per-peer limits, reconnect with backoff, outbox caps | a determined peer can still consume bandwidth |
| D | Topic isolation | preflight compares `STELL_SHARDS` and expected topic | a config error isolates a node with **zero log evidence** |
| E | Bypass auth over WebSocket | WS upgrade honours the same token and peer limits | a proxy that strips headers can change the peer identity |

## Consensus

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Fake votes | Falcon-512 vote signatures verified against the set at the vote's height | a rotated key peers do not know makes votes invalid → downtime jail |
| T | Equivocation (double vote) | 5 % slash on block evidence; evidence verified by every node | evidence capture is locally observed (KI-08) |
| T | Proposal equivocation | active since ruleset v4; same shard/height/signed round, differing hashes | — |
| R | Validator denies a vote | signed votes are attributable; QCs are committed | — |
| I | Early view of ordering | sealed transactions; epoch key released only after ordering is committed | a malicious proposer can still front-run content it sees |
| D | View-change storm | round timeouts, proposer schedule, nil handling, deadlock breaker | repeated view changes can still stall a small set |
| D | Quorum starvation | `quorum = floor(2·power/3)+1`; `fragile` detector | 2- and 3-validator nets halt on one outage |
| D | Stale lock after restart | capped restore, deadlock breaker, `lockclear` | requires operator action |
| E | One node finalizes alone | zero/empty set returns `u64::MAX` quorum; a broken list stalls rather than centralizes | a single validator network is centralized by definition |
| E | Committee grinding | network-anchored quorum; sortition mitigation | proposer-grindable committee remains a medium issue (KI-07) |

**Safety argument in one line:** a block is final only with a precommit
certificate of at least `floor(2·total_power/3)+1`; finalized blocks are never
rolled back, and candidates that lose are reported through the invalidation
feed.

## State and execution

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| T | Non-deterministic execution | single apply path, deterministic clocks, no wall clock in consensus, domain snapshots | a host-specific dependency could still diverge; `diverge` exists to catch it |
| T | Root forgery | Merkle proofs; quorum-certified historical roots; light client verifies a QC against an out-of-band set | the node can lie about the *current* root; verify against a trusted header |
| T | Replay of a transaction | nonce, chain id, payload commitment, signature domain | unbound transactions are still admitted (phase 1) and metered |
| I | Private state leak | proofs reveal the leaf and its witness key; that is ordinary public state | exclusion proofs name the diverging leaf |
| D | State growth | archive vs prune, body cap, snapshot ring | archive mode is unbounded by design |
| D | Expensive unauthenticated read | `stell_estimateFee` has a 5 req/s budget and a fixed 5M gas ceiling | still clones the engine per request |
| E | Contract escape | WASM/SVM sandbox, fuel limit, ABI validation, no EVM interpreter | contract bugs are application bugs, not consensus bugs |
| T | Commitment-domain gap | non-trie domains committed as one digest | cannot prove one staking entry or orderbook level |

## Wallet and keys

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Signature presented under another address | verifier re-derives the address from `(scheme, pubkey)` before checking | — |
| T | Message signature replayed as a transaction | different preimage, domain tags, envelope; see [wallet signing](/sdk/wallets-and-signing) | — |
| T | Transaction signature replayed as a message | verifier rebuilds the prefixed preimage; envelope is not `PQ1` | — |
| T | Cross-chain replay | chain id in message and typed-data preimages | a wallet that ignores `chain_id` is still wrong |
| R | User denies authorizing | signatures are deterministic evidence; typed data shows canonical JSON | off-chain protocols must include a nonce/expiry |
| I | Key theft from disk | key file `0600`, plaintext JSON; node keys encrypted `enc2:` | no HSM/MPC in the SDK |
| I | Key theft from process memory | validator `RemotePqSigner` keeps the key outside the node | remote signing is not HSM-grade without mTLS and policy |
| D | Sidecar unavailable | the JS SDK cannot sign; failure is loud | a compromised sidecar is a signing oracle |
| E | Session key exceeds authority | scope, cumulative gas, expiry, per-tx value cap, terminal revocation | within caps, the master's funds are at risk |
| E | Sponsor exceeds authority | two Falcon-512 signatures, per-tx cap, expiry, allowlist, joint reservation | no on-chain total budget; exposure is `#grants × cap` |

## Faucet (Sybil resistance)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Sybil addresses | per-address lifetime cap (50 STELL) | addresses are cheap; the cap bounds total loss, not the number |
| S | IP rotation | per-IP hourly budget (20) | botnets rotate IPs |
| D | Treasury drain | lifetime cap + per-IP budget + token gate | a token holder can still drain up to caps across addresses |
| D | Nonce grief | one nonce sequence per shard; cross-shard drip refused **before** reserving | a wiped mempool can leave a pending gap; restart reconciles |
| E | Bypass the token | fail-closed without `STELL_FAUCET_TOKEN` | a leaked token is a shared secret |
| T | Corrupt persisted state | fail-closed to empty; never mints extra credit | an operator must investigate the quarantine |

The faucet does not write balances. It signs an ordinary transfer from a
genesis-funded account, so value moves through consensus and can fail like any
transaction.

## Governance capture

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Fake proposal | block-carried `SysCallGovPropose`; sender is the proposer | — |
| T | Vote buying / bribery | weight is self-bond + delegated-out stake, locked until finalize | off-chain bribery is out of scope |
| T | Quorum lowering | floor `GOVERNANCE_QUORUM_FLOOR_BPS = 3333`; a proposal cannot lower below one third | a one-third+ coalition can still change parameters |
| T | Electorate shrink | electorate frozen at propose time; a yes-voter who undelegates cannot shrink the denominator | — |
| R | Double vote | one vote per proposal; recorded weight locked | — |
| D | Proposal spam | 10,000 STELL proposer stake; 3-day window | a large holder can still spam |
| E | Timelock bypass | 90,000-height timelock; `CancelUpgrade` is ungated but only clears | 90,000 heights is short in wall-clock terms (KI-23) |
| E | Oracle capture | publisher allowlist; per-publisher cap; breaker; governance-only reset | per-publisher cap, not median (KI-25) |
| E | Unauthorized execution | `stell_executeProposal` requires a token on every bind; anyone may execute a **passed** proposal | the operator token is a single bearer secret |

## Upgrade

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Fake plan | plan committed in the state digest; marker parsed strictly | a local-only plan cannot hide behind an identical root |
| T | Path traversal | safe name: no `/`, `..`, leading `.`, NUL, non-ASCII; ≤64 bytes | — |
| T | Symlink attack | candidate must be a regular file; parent must be a real directory | — |
| T | TOCTOU | verified bytes are copied to a fresh `0700` dir and **that copy** runs | — |
| T | Wrong binary | exact SHA-256; all-zero never matches | a hash mismatch means the network runs two binaries |
| T | Oversize binary | 512 MiB cap before read | — |
| D | Crash loop | exit 42 + supervisor / `RestartPreventExitStatus=42` | `Restart=always` alone restarts the old binary |
| E | Quorum decides your box | live `execve` is node-local policy, `STELL_AUTO_UPGRADE` default **off** | arming is a deliberate operator choice |
| T | Rollback after `H` | not supported; finalized blocks cannot rewind | only a coordinated new genesis |
| D | `execve` + sled lock | open question; rehearse before arming | a surviving lock can stop the new image |

## Bridge (Teleport)

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Fake relayer | deposit claim carries relayer signatures over the deposit message; 2/3 **distinct** signers counted against the committed staking set | the relayer set is the top target |
| T | Double claim | `processed_source_txs` replay set; second claim `-32003` | — |
| T | Fake deposit | adapter evidence path (math, not testimony) or quorum | the evidence adapter's assumptions are external |
| T | Fraud | quorum retraction over the failure message is the only fraud proof | a colluding supermajority can still lie |
| D | Withdrawal flood | hourly 500k STELL rate limit; cumulative 100M mint cap | global caps, no per-sender limit (KI-28) |
| D | Large withdrawal | 1 h timelock at/above 50k STELL; refund after 24 h | — |
| I | Deposit tracking | `stell_bridgeAttestStatus`, `stell_bridgeDeposits`, dispute countdown | pre-commit claims read `found:false` |
| E | Challenge abuse | challenge bond `max(1 STELL, 1%)`; finder reward 10 % of clawback | deposits older than 24 h cannot be challenged |
| T | Source-chain reorg | TON 12 confirmations; chain-specific finality assumptions | other chains have their own finality models |
| T | Pre-`F-H` restore | loud warning; re-derive caps out-of-band | zeroed counters are a real hazard (KI-29) |

## RPC and indexer

| STRIDE | Threat | Mitigation | Residual |
| --- | --- | --- | --- |
| S | Unauthenticated write | `stell_sendRawTransaction` is open by design; the signature authenticates | spam is bounded by per-IP limiters and pool caps |
| S | Token bypass over WS | WS honours the same token and peer address | a header-stripping proxy can change identity |
| I | Mempool front-running | `stell_mempoolDump` fail-closed without a token | pending contents can aid front-running if leaked |
| D | Request flood | per-IP fixed windows (300/s RPC, 30/s gateway), 1 MiB body, 64-item batch | in-process limiters are a speed bump |
| D | Expensive reads | `stell_estimateFee` 5/s; `stell_getEvents` ≤1000; `getProgramAccounts` bounded | large scans still cost CPU |
| T | Fake chain data from indexer | indexer is a cache, not a proof system | some explorer fields are hard-coded |
| I | Address history correlation | `stell_getAddressHistory` is public | on-chain history is public by design |
| E | EVM address hijack | binding requires a 65-byte secp256k1 proof of possession; first claim wins | an unbound address can be claimed by any PQ key (naming grief, C1) |

## Assumptions (not defended)

- The host is not rooted. A rooted host owns the keys.
- The hardware supply chain is honest.
- SHA-256, BLAKE3, Ed25519, Falcon-512 and curve25519 are not broken.
- A >1/3-stake adversary can stall; a >2/3-stake adversary can finalize what it
  wants. Economic finality is out of scope.
- The operator configures the same `STELL_SHARDS`, chain id, genesis inputs and
  timeouts on every node.
- The remote signer's network and policy are configured by the operator.
- Off-chain bridges, exchanges and custodians apply their own confirmation
  policy.

## Residual risk register

| Risk | Severity | Status |
| --- | --- | --- |
| No external audit | critical (assurance) | open |
| Relayer-based bridge | high (bridge-scoped) | open by design |
| No user multisig | high (custody) | documented non-goal |
| Governance timelock short in wall-clock | medium | open |
| Sortition grindable | medium | mitigated, VRF out of scope |
| Equivocation evidence local | medium | open |
| MEV seal vs malicious proposer | medium | residual |
| No live shard split | medium | open |
| Snapshot gap deadlock on a halted chain | high (DR) | documented; set `STELL_SNAPSHOT_INTERVAL ≤ 156` |
| `execve` + sled lock | unknown | rehearse |
| Indexer presentation data | low (correctness) | documented |
| Faucet Sybil | low (testnet) | capped |

## Next

Read [Security status](/security/status) for the audit and known-issue record, then [Reporting](/security/reporting) for private disclosure.
