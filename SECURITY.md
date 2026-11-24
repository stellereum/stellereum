# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `main` / `full-pq-testnet-*` (Ruleset v7, chain 5757) | ✅ |
| Tagged releases `v*` (see the Release workflow) | ✅ for the latest tag |
| Older tags | ❌ — upgrade before reporting a fix that depends on them |

## Reporting a vulnerability

Please report privately, not in a public issue:

- **GitHub private advisory** (preferred):
  <https://github.com/stellereum/stellereum/security/advisories/new>
- **X/Twitter DM**: <https://x.com/stellereum>

Include: affected commit/tag, the component (consensus, storage, RPC, faucet,
contracts, SDK, indexer), reproduction steps, and the impact you believe it has.

**Do not** open a public issue, post proof-of-concept transaction payloads, or
test against the live validator set (denial of service against the four live
nodes is not authorised, even in a "safe" form).

## What we promise

| Step | Target |
|---|---|
| Acknowledgement | 3 business days |
| Triage + severity (CVSS) | 10 business days |
| Fix or mitigation for Critical/High | 30 days |
| Coordinated disclosure | 90 days, or earlier by agreement |
| Credit | in the advisory and the release notes, unless you prefer otherwise |

We will tell you if a report is out of scope, duplicated, or not reproducible,
and why. We will not silently close a report.

## In scope

- Consensus safety and liveness (`stellereum/src/consensus`, `safety.rs`,
  `consensus_net.rs`, `node/*`), including the `SafetyAuthority` watermark and
  the µQC/attribution paths.
- Post-quantum crypto misuse (Falcon-512, ML-KEM-768), signature-domain and
  chain-id binding, key handling.
- Storage integrity (state root, snapshots, schema), replay and cross-shard
  isolation.
- RPC, explorer, faucet (anti-sybil, rate limiting), indexer API.
- Contracts under `stellereum-contracts/` and the SVM host functions.
- Supply chain: dependency confusion, unsigned release paths, CI credentials.

## Out of scope (as of this policy)

- Denial of service by sheer volume against public endpoints (report it, but it
  is not a bounty case).
- Findings that require the validator's own private key.
- Demo-grade reference contracts documented as such in `docs/OPEN_DEFECTS.md`
  unless the issue allows theft of funds from a *different* account.
- Testnet-only misconfiguration that cannot affect mainnet deployment.

## Hardening already in place (for context, not a substitute for a report)

FULL-PQ end to end (Falcon-512 votes, ML-KEM-768 transport), fail-closed safety
quarantine, durable write-ahead watermarks, chain-bound signatures, per-peer
admission budgets, and a defect register with a regression test per fix
(`docs/OPEN_DEFECTS.md`). Release artifacts are built with `--locked`, shipped
with an SBOM, and signed keyless with cosign — see `docs/RELEASE.md` for how to
verify a binary before you run it.

## CVE process

1. A privately reported issue is confirmed and given a CVSS vector.
2. A fix lands with a regression test; the test name goes into
   `docs/OPEN_DEFECTS.md`.
3. If the issue is exploitable on a deployed network, an advisory is published
   with the affected versions, the mitigation, and the fixed version — after
   operators have had the agreed window to upgrade.
4. Only then is the detail published.
