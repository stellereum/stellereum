---
title: Security status
description: Testnet software, no external audit, internal review waves and what is not covered.
outline: deep
---

# Security status

Stellereum is testnet software and no independent party has attested it. This page records the review history, the mechanisms that are implemented and tested, and the limits that remain. Read it before you run a validator, bridge an asset or treat a green internal test run as assurance.

::: danger Testnet only — no real funds
Testnet coins have no value. There is **no independent external audit**. Do not
bridge, hold, or promise custody of real value. Run a validator only with keys
and stake you can lose.
:::

## Audit history

No independent party has attested this code. The project has run internal
review waves, a reproducible audit harness and penetration-test batteries, and
it documents its known issues in-tree. That is **transparency, not assurance**.
Assume consensus, bridge, wallet, RPC and indexer bugs exist.

| Activity | Status | What it means |
| --- | --- | --- |
| External audit | **none completed** | no third-party attestation |
| Internal review waves | cited in code/docs: W6.1 Falcon repair, W6.7 upgrade-staging re-audit, W8.3 light client + zkML rename + `stell_zkmlCapabilities`, W10.5 quorum-activation race | internal review, not external assurance |
| Reproducible audit harness | `scripts/audit-repro.sh`; the `EXTERNAL_AUDIT_BRIEF.md` repro table printed **87 components: 86 green, 1 red, 0 errored** on its 2026-10-30 run | re-run the script before quoting it; a moving tree changes the count |
| Fuzz corpora | 2,000 cases each over frame/consensus/tx/block/cert/EVM/peer decoders (per the same brief) | fuzzing is evidence, not proof |
| Pentests | many `pentest*` harnesses, including `stl57_audit_pentest` (address parsing: homoglyph, checksum, length) | **not** a substitute for an external network pentest |
| Formal verification | none | no machine-checked protocol proof |

The auditor entry point is `EXTERNAL_AUDIT_BRIEF.md`. It is a brief, not a
report. A green internal harness does not make the system audited.

## What is implemented and tested

These are real, in-tree mechanisms with tests. “Tested” still does not mean
“audited”.

- **Falcon-512 / FIPS 206** credential path; ML-DSA-44 is disabled fail-closed.
- **PQ1 and SF1 transaction envelopes, plus SP1 sponsor grants**; explicit and implicit PQ1, session grants,
  sponsor grants.
- **Single-block BFT finality** with precommit quorum certificates;
  `quorum = floor(2·power/3)+1`.
- **Chain-id binding** in envelopes and signing preimages; the SDK mirrors the
  fork id and refuses a foreign chain before signing.
- **State proofs**: inclusion and exclusion proofs, archive proofs at snapshot
  heights, historical roots with QCs.
- **Light client** (`stellereum light-client`) that verifies a proof against a
  quorum-certified header using an **out-of-band** validator set.
- **Governance** with a bounded quorum floor, a 3-day vote, a 90,000-height
  timelock and committed plans.
- **Upgrade staging**: safe name, regular file, size cap, exact SHA-256,
  private copy of the verified bytes, parent-directory check.
- **Wallet message signing** with domain separation and chain binding.
- **Faucet** with fail-closed token, per-IP hourly budget, lifetime cap, and
  **salted-IP privacy**: hourly rate-limit buckets store only a truncated
  keyed BLAKE3 digest (`BLAKE3_KEYED(salt, normalized_bucket)[..16]` hex, using
  a persisted `faucet_ip_salt_v1` salt after IPv4 / IPv6 `/64` normalization),
  never raw client IP addresses in memory or persisted state
  (`stellereum/src/rpc/faucet.rs`).
- **Release supply-chain verification**: tagged `v*` releases build with
  `--locked`, run `cargo-deny` and `cargo-audit` in CI, publish an SPDX SBOM,
  and are signed keyless with `cosign` (`docs/RELEASE.md`).
- **Remote PQ signer** for validator consensus keys, with pinned key and no
  local fallback.
- **Session keys** with scope, cumulative gas budget, expiry and terminal
  revocation.
- **Paymaster v2** with two Falcon-512 signatures, per-transaction caps and joint reservation.

## Security policy, CVE process, and `security.txt`

`SECURITY.md` at the repository root defines the vulnerability reporting and
CVE process, and `/.well-known/security.txt` (RFC 9116, served on both
`docs.stellereum.org` and `stellereum.org`) points researchers to the private
channels:

- **Private reporting:** GitHub Security Advisories
  (`https://github.com/stellereum/stellereum/security/advisories/new`,
  preferred) or X/Twitter DM (`https://x.com/stellereum`). Do not open public
  issues, post PoCs, or run unauthorized DoS against the live 4-node set.
- **Targets (`SECURITY.md`):** 3 business days acknowledgement, 10 business days
  triage + CVSS severity, 30 days fix or mitigation for Critical/High, and
  90 days coordinated disclosure (or earlier by agreement).
- **CVE handling:** confirmed reports receive a CVSS vector and a fix pinned by
  a regression test recorded in `docs/OPEN_DEFECTS.md`; if exploitable on a
  deployed network, an advisory (affected versions, mitigation, fixed version)
  is published after the agreed operator upgrade window, with technical details
  released only afterwards.

## What is NOT covered

This is the list to read before trusting a claim.

### No external audit, no bug bounty

There is **no standing bounty program**. Private disclosure channels are active
via `SECURITY.md` and `/.well-known/security.txt` (see [Reporting](/security/reporting)),
but internal reviews and harnesses do not substitute for an external audit.

### Consensus and network

- No live **shard split** has been performed. Sharding topology and split/merge
  rules are tested synthetically; the public deployment is one shard (`{0}`) or
  the fixed `{0,1}` pair.
- Sortition committee grinding is a documented medium issue, mitigated by a
  network-anchored quorum; a VRF is out of scope / not wired.
- Proposal-equivocation evidence is locally observed; evidence in the commit
  certificate is a known gap.
- The network is not battle-tested under adversarial load at mainnet scale.
- A halted 2-of-4 cluster cannot self-recover if the snapshot gap exceeds the
  256-block walk cap. This is a **documented disaster-recovery deadlock**; a
  filesystem backup is mandatory.
- Mixed versions fail closed, but exact-match frame versions mean a partial
  rollout isolates nodes.

### State and execution

- The state root commits non-trie subsystems (staking, order books, PMM,
  contracts, governance, oracle) as **one digest**, not per key. A client can
  prove a native balance, not a single staking entry.
- Reading `stell_getStateRoot` has a side effect on first read after a mutation.
- No user-level multisig or threshold accounts. One key authorizes one
  transaction. The only “multisig” is the bridge relayer 2/3 quorum, not user
  custody.
- Contract execution is a WASM/SVM path, not EVM. There is **no EVM
  interpreter** and no EVM state trie; EVM calldata and contract creation are
  refused.
- zkML is a **sound re-execution attestation**, not a zero-knowledge proof.
  `stell_zkmlCapabilities` says so in machine-readable form: `zero_knowledge`,
  `succinct`, `hiding` and `trusted_setup` are all `false`.
- Source verification proves byte-identical rebuild, not safety. A verified
  backdoor is still a backdoor.

### Wallet and keys

- The SDK key file is **plaintext JSON at mode 0600**. No encrypted keystore,
  hardware wallet, HSM or MPC in the SDK.
- JavaScript does not sign Falcon. The TypeScript SDK delegates to a Rust
  subprocess or localhost HTTP helper; the signer is trusted with the key.
- The node operator key container is not importable into the SDK.
- Remote signing removes the key from process memory but is **not** HSM-grade
  by itself: the operator must authenticate/encrypt the link, restrict what the
  signer will sign, pin the endpoint and fail closed.
- The legacy Ed25519 `RemoteSigner` cannot sign Falcon votes; full-PQ
  validators need `RemotePqSigner` or a local `falcon.key`.

### Bridge

- The bridge is **relayer-based**, not light-client-based. The signer set is
  the top target.
- A deposit is admitted by relayer quorum or adapter evidence; a fraud proof is
  a quorum retraction over a failure message.
- Pre-`F-H` bridge restores zero the mint counters; caps must be re-derived
  out-of-band. This is loud and open.
- No per-sender bridge rate limit; global hourly and cumulative caps hold.
- TON finality is 12 masterchain confirmations; other chains have their own
  assumptions.

### MEV and privacy

- The sealed/epoch-key path hides transaction **content** from the public pool,
  not from a malicious proposer. Proposer self-frontrunning is a residual.
- Privacy work is unwired, default-OFF prototypes (HashPool / SilentPay /
  Dandelion): stealth + CoinJoin unlinkability only, **no amount hiding**,
  nothing to call over RPC.
- The shielded/Ristretto path was **removed**; `stell_shielded*` and
  `stell_unshield` return `-32601`.

### Governance

- The 90,000-height timelock is short in wall-clock terms (~75 min at the 50 ms
  floor, hours at live tempo). It is not a long human review window.
- Oracle actions cannot be executed through `stell_executeProposal`; they fail
  closed and must go through the block-carried sweep.
- Governance capture is bounded by a quorum floor of one third, but a
  sufficiently large stake majority can still change parameters.
- The governance write RPC is token-gated, but the token is a single bearer
  secret. Protect it.

### RPC and indexer

- The RPC token is optional and is the only write gate for some arms. The
  gateway limiter is a speed bump, not access control.
- `stell_getBlock` serves only a 100-entry rolling window; there is no block
  body over RPC.
- Receipts are indexed for only 50,000 entries.
- `stell_getTransactionReceipt` has three result shapes; `pending` only knows
  **this node's** mempool.
- The indexer is a cache, not a proof system. Some explorer endpoints are
  hard-coded presentation data. It exposes no `/health` or `/metrics`.
- EVM bindings are a **node-local replay index**, not a state-root domain, and
  are first-committed-wins. A restarted node starts empty until bindings are
  re-observed; this can under-report balances and refuse carriers, never fork
  value.
- `eth_estimateGas` is an admission estimate, not execution metering.

### Operations

- 1 vCPU is explicitly insufficient; the shipped units are hardened for it,
  not validated for production.
- `Restart=always` plus exit 42 is a crash loop unless you use a supervisor or
  `RestartPreventExitStatus=42`.
- The `STELL_AUTO_UPGRADE=1` `execve` path has an open question about the sled
  lock surviving `execve`; rehearse before arming.
- Backup policies in the tree contradict each other on whether `keys/` is
  copied. For host loss, you need an encrypted keys archive.
- No external evidence that the restore or upgrade drills have been run on the
  live 4-node set.

## Known issues

The in-tree `stellereum/docs/audits/KNOWN_ISSUES.md` carries KI-01…KI-41 with severity,
exploitability and audit action. Read it before reporting; your finding may be
a documented non-goal (for example user multisig, §J D-11).

Representative entries:

| ID | Issue | Status |
| --- | --- | --- |
| KI-26 | bridge is relayer-based, no light client | open by design; signer set is the top target |
| KI-02 | legacy Falcon path had ~32 bits entropy | removed; strict-only derivation |
| KI-01 | ML-DSA-44 verifier is not FIPS-204 | fail-closed (`from_id(3)` errs) |
| KI-29 | pre-`F-H` bridge restore zeroes mint counters | open and loud; re-derive caps out-of-band |
| KI-07 | sortition committee grindable by proposer | mitigated by network-anchored quorum |
| KI-08 | equivocation evidence locally observed | open; needs evidence in the commit cert |
| KI-09 | restarted node resumed stale round | mitigated (capped restore + deadlock breaker) |
| KI-19 | RPC token is the only write gate (optional) | open; set the token, keep RPC on loopback |
| KI-23 | governance timelock is short in wall-clock terms | open; set plan heights days out |
| KI-25 | oracle rule is a per-publisher cap, not median | open |
| KI-28 | no per-sender bridge rate limit | open; global caps hold |
| KI-30 | no live-network shard split performed | open |
| KI-31/33 | zkML is sound re-execution, not ZK/SNARK | open by design |
| KI-34 | MEV seal hides content, not from a malicious proposer | residual |
| KI-11 | bincode accepts trailing bytes | open; never byte-dedup envelopes |

## What “unaudited” means for users

Concretely:

- run a validator only with keys you can lose;
- never bridge, hold, or promise custody of real value;
- verify `stell_getStateRoot` agreement and finalized-header QCs yourself rather
  than trusting one endpoint;
- treat a single RPC or indexer as a convenience, not an authority;
- read `KNOWN_ISSUES.md` before reporting;
- assume the worst about a green internal test run.

## Next

Continue with the [Threat model](/security/threat-model) for the assets and trust boundaries, then [Reporting](/security/reporting) if you find a vulnerability.
