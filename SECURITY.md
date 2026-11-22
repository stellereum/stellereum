# Security Policy — Stellereum

> **Status: DRAFT for the owning org to complete before mainnet.**
> The contact address, PGP key and bounty terms below are **placeholders**
> the organisation MUST replace. A policy that still contains
> `REPLACE-ME` / `[LEAD-SETS-EMAIL]` is not shippable.
>
> **Testnet only — no real funds.** Testnet coins have no value. Do not attack
> live systems without explicit written permission (see below).

## Scope

This policy covers the node, contracts, and indexer that decide consensus,
hold funds, or face the network:

- the L1 node and consensus engine (`stellereum/src/`, in particular
  `consensus.rs`, `runtime.rs`, `state_engine.rs`, `staking.rs`,
  `governance.rs`, `svm.rs`, `storage.rs`, `bridge.rs`, `rpc.rs`,
  `explorer.rs`, `post_quantum.rs`);
- the wallet and key management (`stell-wallet/`, `stellereum/src/wallet.rs`,
  `stellereum/src/node_keys.rs`);
- the operator tooling operators are told to trust
  (`stellereum/scripts/`, `scripts/` at the repository root,
  `scripts/tools/stelops/`);
- the indexer and explorer that users read state from
  (`stellereum-indexer/`, `explorer-site/`).

Out of scope: third-party dependencies (report upstream, but tell us —
see below), the `infnode` transport layer's own repository (same rule),
and social-engineering / physical-security reports concerning individuals.

Threat model and known weaknesses live in-tree:
`stellereum/docs/audits/THREAT_MODEL.md` and
`stellereum/docs/audits/KNOWN_ISSUES.md`. Read them before reporting —
your finding may be a documented non-goal (e.g. user-level
multisig/threshold accounts, §J D-11) rather than a vulnerability.

## How to report

- **Email:** `[LEAD-SETS-EMAIL]` — **PLACEHOLDER, LEAD SETS THE REAL ADDRESS
  BEFORE MAINNET.** The real address must be a monitored, access-controlled
  mailbox owned by the core team (e.g. `security@stellereum.org`).
- Encrypt with the PGP key below. If you cannot use PGP, say so in the
  subject line (`[no-pgp]`) and we will open a secure channel.
- Include: affected component + version/commit, steps to reproduce or a
  minimal PoC, impact assessment (funds at risk? consensus safety?
  liveness?), and whether the issue is already public.
- **Do NOT** open a public GitHub issue, post a PoC, or discuss the
  finding in public channels before we have confirmed the fix.

## Response SLA

| Step | Target |
| --- | --- |
| Acknowledge receipt | **2 business days** |
| Initial triage (valid / invalid, severity) | **5 business days** |
| Fix timeline for a confirmed Critical/High | communicated at triage, updated weekly |
| Public advisory + credit | with the fix release, or **90 days** after the report, whichever the reporter agrees to |

If you hear nothing within the acknowledgement window, assume the mail
was lost and re-send with `[resend]` in the subject.

## Safe harbor

We will not pursue civil action, criminal referral, or ask a platform to
suspend your account for security research conducted **in good faith**
under this policy. Good faith means:

- you test only systems you are authorised to test (your own nodes,
  the public testnet — never someone else's mainnet funds or infrastructure);
- you do not exfiltrate, destroy, or ransom data, and you stop and report
  as soon as you have enough to demonstrate impact;
- you do not use the finding for profit (no front-running, no theft,
  no extortion) and you give us the triage window above before disclosing.

Research that violates these conditions (active exploitation of mainnet
funds, data destruction, extortion) is outside this safe harbor.

## PGP

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
REPLACE-ME: the owning org MUST publish the real security-contact
public key here before mainnet. Until this block is replaced, encrypt
to the mailbox above and note "[no-pgp]" per the reporting section.
-----END PGP PUBLIC KEY BLOCK-----
```

Key rotation: the fingerprint of the current key is announced in the
release notes of every release. Verify the fingerprint out-of-band
before trusting an updated block.

## Supported versions

| Deployment | Support |
| --- | --- |
| Latest tagged release (`git tag`, `CHANGELOG` if present) | full support — patches + advisories |
| Previous minor release | best-effort patches for Critical severity only, for 90 days |
| `main` between releases, testnets, simulators, examples, fuzz targets | fixes land here first, but no advisory SLA |
| EOL releases (announced in release notes) | no patches; upgrade |

The chain-id binding (`PROTOCOL.md` §2a) means a testnet finding and a
mainnet finding are different findings — say which deployment you tested.

## What happens after you report

1. **Triage.** We reproduce against the in-scope code, assign a severity
   using the `REMOTE / VALIDATOR / OPERATOR / LOCAL` exploitability
   vocabulary of `KNOWN_ISSUES.md`, and confirm whether the code or the
   documentation is at fault.
2. **Fix.** Developed privately, pinned by a regression test, reviewed
   against the in-tree invariants (`PROTOCOL.md`, `INVARIANTS.md`).
3. **Advisory.** Published with the fix release: affected versions, impact,
   mitigation, credit (with your consent — anonymous credit is fine).
4. **Bounty, if any.** There is **no standing bounty program yet**
   (PLACEHOLDER — the org must either publish terms here or delete this
   line before mainnet; do not imply a bounty that does not exist).
   Severity-equivalent recognition (credit, references) is given in all cases.

## Ground rules for operators (the 30-second version)

- Node keys are encrypted at rest by default (`enc2:` format,
  `src/node_keys.rs`) — keep the passphrase out of shell history, CI logs
  and the repository.
- The RPC port has no rate-limiting of its own; the gateway limiter is a
  speed bump, not access control. Keep `STELL_RPC_LISTEN` /
  `STELL_EXPLORER_LISTEN` on loopback unless you have read §6 of
  `stellereum/docs/OPERATIONS.md`.
- Never run a faucet with the test seed (`0x11..11`) or a placeholder
  `STELL_FAUCET_KEY` — it is public in this repository.
