---
title: Reporting a vulnerability
description: Private disclosure, scope, safe harbour and response times — and why never to open a public issue.
outline: deep
---

# Reporting a vulnerability

Security reports are handled privately. This page defines where to send a finding, what is in scope, the severity vocabulary and the response targets, so a report arrives with enough detail to reproduce and triage.

::: danger Never open a public issue for a suspected vulnerability
Do not open a GitHub issue, post a proof of concept, or discuss the finding in
a public channel before the maintainers have confirmed a fix. A public report
turns a bug into an exploit.
:::

## Where to report

Use the private channels defined in `SECURITY.md` at the repository root and
advertised at `/.well-known/security.txt` (RFC 9116):

- **GitHub private advisory** (preferred):
  `https://github.com/stellereum/stellereum/security/advisories/new`
- **X/Twitter DM**: `https://x.com/stellereum`

Do **not** open a public issue, post proof-of-concept transaction payloads, or
test against the live validator set (denial of service against the four live
nodes is not authorized, even in a "safe" form).

Include:

1. **Component and version** — crate, file, commit or release tag.
2. **Reproduction** — minimal steps or a PoC. A failing test is ideal.
3. **Impact** — funds at risk? consensus safety? liveness? privacy? operator
   tooling?
4. **Preconditions** — remote peer, validator, operator, local access, token,
   specific config.
5. **Disclosure status** — is it already public anywhere?
6. **Your preferred credit** — name, handle or anonymous.

Do not send real user keys, mainnet funds or third-party data.

## Scope

In scope:

- the L1 node and consensus engine (`stellereum/src/`), especially consensus,
  runtime, state engine, staking, governance, SVM, storage, bridge, RPC,
  explorer, post-quantum crypto, wallet and node keys;
- the wallet and key management (`stell-wallet/`,
  `stellereum/src/wallet.rs`, `stellereum/src/node_keys.rs`);
- operator tooling operators are told to trust (`stellereum/scripts/`,
  root `scripts/`, `scripts/tools/stelops/`);
- the indexer and explorer (`stellereum-indexer/`, `explorer-site/`);
- the SDKs (`stellereum-sdk/`, `sdk-js/`) where a bug breaks a security
  property (signature domain, chain binding, key handling, signer boundary);
- the upgrader (`stellereum-upgrader/`).

Out of scope:

- third-party dependencies — report upstream, but tell us so we can pin or
  mitigate;
- the `infnode` transport layer's own repository (same rule: report upstream,
  tell us);
- social engineering, phishing or physical security against individuals;
- a documented non-goal (read `stellereum/docs/audits/KNOWN_ISSUES.md` first);
- “the testnet has no audit” as a finding;
- spam/DoS that only demonstrates the known in-process rate limiter;
- a finding that requires a rooted host or a stolen key, unless the issue is
  how the system handles that compromise.

## Severity vocabulary

The project uses the exploitability classes from `KNOWN_ISSUES.md`:

| Class | Meaning |
| --- | --- |
| `REMOTE` | an unauthenticated network peer can trigger it |
| `VALIDATOR` | requires a validator identity or stake |
| `OPERATOR` | requires operator access or config control |
| `LOCAL` | requires local code execution or the key itself |

Severity is impact × exploitability. A `LOCAL` finding that steals funds is
still serious; a `REMOTE` finding that only logs noise is not critical.

## Response targets

| Step | Target |
| --- | --- |
| Acknowledge receipt | **3 business days** |
| Triage + severity (CVSS) | **10 business days** |
| Fix or mitigation for Critical/High | **30 days** |
| Coordinated disclosure | **90 days**, or earlier by agreement |
| Credit | in the advisory and the release notes, unless you prefer otherwise |

We will tell you if a report is out of scope, duplicated, or not reproducible,
and why. We will not silently close a report.

## CVE process

1. A privately reported issue is confirmed and assigned a CVSS vector.
2. A fix lands with a regression test; the test name is recorded in
   `docs/OPEN_DEFECTS.md`.
3. If exploitable on a deployed network, an advisory is published with affected
   versions, mitigation, and the fixed version after operators have had the
   agreed upgrade window.
4. Technical details are published only after that advisory/upgrade window.

## Safe harbour

The project will not pursue civil action, criminal referral, or ask a platform
to suspend your account for security research conducted **in good faith**
under the policy. Good faith means:

- you test only systems you are authorized to test — your own nodes and the
  public testnet, **never** someone else's mainnet funds or infrastructure;
- you do not exfiltrate, destroy or ransom data, and you stop and report as soon
  as you have enough to demonstrate impact;
- you do not use the finding for profit (no front-running, no theft, no
  extortion) and you give the triage window above before disclosing;
- you do not degrade the testnet for other users beyond the minimum needed to
  demonstrate the issue.

Research that violates these conditions — active exploitation of mainnet funds,
data destruction, extortion — is outside the safe harbour.

## No bounty

There is **no standing bounty program**. Do not imply one exists. Credit and
references are given with consent; anonymous credit is fine.

## What happens after you report

1. **Triage.** The maintainers reproduce against the in-scope code, assign a
   severity class and confirm whether the code or the documentation is at
   fault.
2. **Fix.** Developed privately, pinned by a regression test, reviewed against
   the in-tree invariants.
3. **Advisory.** Published with the fix release: affected versions, impact,
   mitigation, credit.
4. **Recognition.** Credit or references; no monetary bounty.

## If you are an operator

- Keep `STELL_RPC_LISTEN` and `STELL_EXPLORER_LISTEN` on loopback unless you
  have read the exposure checklist.
- Set `STELL_RPC_AUTH_TOKEN` and `STELL_FAUCET_TOKEN`; the token is the only
  write gate for several arms.
- Keep node keys encrypted; keep the passphrase out of shell history, CI logs
  and the repository.
- Never run a faucet with the test seed (`0x11…11`) or a placeholder key.
- Back up `keys/` and `node.env` together, encrypted, off-host.
- Watch stderr, not only structured logs.
- If you suspect a compromise, preserve evidence first: stop the unit, copy
  `data/`, `keys/`, `node.env` and the journal, then rotate keys on-chain.

## Next

Read [Security status](/security/status) for what is and is not covered, and [Threat model](/security/threat-model) for the trust boundaries. [Operations](/nodes/operations) covers evidence preservation during an incident.
