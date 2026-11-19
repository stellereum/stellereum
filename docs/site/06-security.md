# Security

## Threat model (plain language)

Three attacker classes (`docs/audits/THREAT_MODEL.md`, STRIDE per
subsystem): **E1 remote peer** (arbitrary bytes to P2P/RPC, cannot forge
signatures or read disk) · **E2 validator** (E1 + stake: can sign,
equivocate, grind sortition, front-run with its own tx) · **E3 operator**
(disk, env, local code: misconfiguration, key theft). Assumed, not
defended: rooted host, hardware supply chain, broken SHA-256/BLAKE3/
Ed25519/BLS/Falcon/curve25519, 51 %-of-stake. In one line: the network
distrusts peers (verify everything: signatures, QCs against the *local*
set, order roots, shard-head sets, 2PC proofs against anchored roots),
distrusts its own timers for punishment (slash only on block evidence),
and distrusts its operators' memory (genesis fingerprint refuses to start
on a changed chain rather than silently forking).

## Audit history

- **Internal review waves** (cited in code/docs: W6.1 Falcon repair,
  W6.7 upgrade-staging re-audit, W8.3 light-client + zkML rename +
  `stell_zkmlCapabilities`, W10.5 quorum-activation race). The
  `EXTERNAL_AUDIT_BRIEF.md` repro table prints **87 components: 84 green,
  2 red, 1 errored** (`scripts/audit-repro.sh`; includes fuzz corpora at
  2000 cases each over frame/consensus/tx/block/cert/EVM/peer decoders).
- **Pentests:** the `stl57_audit_pentest` suite (5 tests: homoglyph,
  checksum, length-guard) is the only in-tree suite literally named
  pentest — do not inflate this into a network pentest claim.
- **External audit: none completed.** The repo banner (`README.md:1`)
  states it: internal audits + penetration tests passed, **no independent
  external audit yet**. `EXTERNAL_AUDIT_BRIEF.md` is the auditor entry
  point, not a report.
- TODO: confirm the current red/errored suites and wave numbering.
  Verify: `bash scripts/audit-repro.sh --no-fuzz 2>&1 | tail -n 10`.

## Known issues (top 15 of KI-01…KI-36)

Severity + status quoted from `docs/audits/KNOWN_ISSUES.md`:

| ID | Issue | Severity | Status |
| --- | --- | --- | --- |
| KI-26 | bridge is relayer-based, no light client | HIGH (bridge-scoped) | open by design — signer set is the top target |
| KI-02 | legacy Falcon path has ~32 bits entropy | CRITICAL if enabled | open by design, loud error, rotate via `keys rotate-falcon` |
| KI-01 | ML-DSA-44 verifier is not FIPS-204 | CRITICAL if enabled / INFO shipped | fail-closed (`from_id(3)` errs) |
| KI-29 | pre-F-H bridge restore zeroes mint counters | HIGH if mishandled | open and loud — re-derive caps out-of-band |
| KI-07 | sortition committee grindable by proposer | MEDIUM | mitigated by network-anchored quorum; VRF out of scope |
| KI-08 | equivocation evidence locally observed | MEDIUM | open — needs evidence in the commit cert |
| KI-09 | restarted node resumes stale round | MEDIUM (liveness) | open — coordinated wipe; see lockclear |
| KI-19 | RPC token is the only write gate (optional) | MEDIUM | open — set `STELL_RPC_AUTH_TOKEN`, keep RPC on loopback |
| KI-23 | governance timelock is short in wall-clock terms | MEDIUM | governed actions are scheduled `+7,200` heights after finalize (`GOV_TIMELOCK_HEIGHTS`), which is minutes at the 50 ms floor — not a long human review window |
| KI-25 | oracle rule is a per-publisher cap, not median | MEDIUM | open — 5 %/feed, 10 % latches 3-day breaker |
| KI-28 | no per-sender bridge rate limit | MEDIUM | open — global caps hold regardless |
| KI-30 | no live-network shard split performed | MEDIUM | open — synthetic-set tests only |
| KI-31/33 | zkML is sound re-execution, not ZK/SNARK | MEDIUM (expectation risk) | open by design — read `stell_zkmlCapabilities` |
| KI-34 | MEV seal hides content, not from a malicious proposer | MEDIUM (economic) | live threshold seal; proposer self-frontrunning residual |
| KI-11 | bincode accepts trailing bytes | MEDIUM | open — never byte-dedup envelopes |

Remaining 21 (BLS-off KI-04, commitment-recompute KI-15, archive KI-16,
light-client trust KI-18, plaintext legacy keys KI-20, …): read the file;
every entry names file, line, exploitability and audit action.

## Bug bounty

There is **no standing bounty program**. Report via `/SECURITY.md` at the
repo root: scope (consensus, funds, network-facing, wallet, ops tooling,
indexer/explorer), 2-business-day acknowledgement / 5-day triage SLA,
good-faith safe harbor (own nodes + public testnet only, no
exfiltration/extortion, no mainnet-funds testing). **Contact email and PGP
block are `REPLACE-ME` placeholders — the owning org must replace them
before mainnet; a policy still containing them is not shippable.**
Do not open a public issue for a suspected vulnerability.

## What "unaudited" means for users

No independent party has attested the code. Internal waves + the repro
table + 36 documented known issues are transparency, not assurance:
assume consensus, bridge, wallet and RPC bugs exist. Concretely: run a
validator only with keys you can lose; never bridge, hold, or promise
custody of real value; verify `stell_getStateRoot` agreement and
finalized-header QCs yourself rather than trusting one endpoint; and read
`KNOWN_ISSUES.md` before reporting — your finding may be a documented
non-goal (e.g. user multisig, §J D-11).
