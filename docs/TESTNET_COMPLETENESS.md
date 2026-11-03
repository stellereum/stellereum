# Testnet Completeness Audit (HDAE, 2026-11-03, read-only)

Sources: `FEATURES.md` (102 GREEN / 1 RED / 1 SKIP), `docs/PUBLIC_TESTNET_CODE_GAPS.md`
(lead freeze, 2026-11-03), code+tests (every `file:line` below grep/execution-verified).
Rule: no existing file modified; this is the single new doc.

## 1. Journey table (17 steps: 17 PRESENT / 0 missing-code, 4 with caveats)

| # | Step | Verdict | Proof |
|---|---|---|---|
| V1 | validator keygen | PRESENT | `stellereum/src/node_keys.rs:686` `load_or_generate_node_keys`; `stell-wallet/src/main.rs:5401` `pq-generate`; FEATURES `pq-keygen-sign-verify` GREEN |
| V2 | bond (min 1100 STELL) | PRESENT | `stellereum/src/native_api.rs:191,637` `stell_stakeBond`→`SysCallStake`; `stellereum/src/staking.rs:59,75` floor; `stell-wallet/src/main.rs:902` `stake_opcode` |
| V3 | elected (top-250) | PRESENT (code) + live-proof GAP (Major, §3) | `stellereum/src/staking.rs:1981` truncate 250; `:1988` `elected_count`; `stellereum/src/rpc.rs:5507` `stell_getValidators`, `:5461` `stell_getValidatorStatus`; join doc `docs/site/04-validators.md:102` |
| V4 | rewards | PRESENT | `stellereum/src/staking.rs:2979` `distribute_reward`; `:3135` `claim_validator_rewards`; `stellereum/src/native_api.rs:226` `stell_claimRewards` |
| V5 | unbond (2-day cooldown) | PRESENT | `stellereum/src/staking.rs:228` `UNBONDING_PERIOD_SECS = 2*24*3600`; `stell-wallet/src/main.rs:208,232,244` unbond/begin-unbond/withdraw-unbond; `stellereum/src/native_api.rs:198,205` |
| C1 | faucet drip | PRESENT (code) + anti-sybil GAP (Blocker-ops, §3) | `stellereum/src/rpc.rs:4691` `stell_faucet`; `:332` `FAUCET_IP_MAX_PER_HOUR=20`; `:339` override; FEATURES `faucet-pq` GREEN |
| C2 | transfer | PRESENT | `stellereum/src/rpc.rs:5910` `stell_sendRawTransaction`; `stellereum/src/native_api.rs:127` `stell_tokenTransfer`; `stell-wallet/src/main.rs:5086` pay/send |
| C3 | fees | PRESENT | `stellereum/src/rpc.rs:5838` `stell_estimateFee`; FEATURES `fee-determinism`, `pq-fee` GREEN |
| D1 | deploy contract | PRESENT | `stellereum/src/rpc.rs:6467` `stell_deployContract`; FEATURES `contracts-node-side`, `sts20/dns/pool/account-onchain` GREEN |
| D2 | call contract | PRESENT | `stellereum/src/rpc.rs:6737` `stell_callContract`; FEATURES `evm-flows` 92 passed GREEN |
| D3 | events | PRESENT | `stellereum/src/rpc.rs:5283` `stell_getEvents`; `:1435` receipts-with-events; FEATURES `explorer-ux` GREEN |
| E1 | explorer balance | PRESENT | `stellereum/src/rpc.rs:4814` `stell_getBalance`; `stellereum/src/explorer.rs:1091` `/api/account/:address`; FEATURES `indexer-api` GREEN |
| E2 | explorer tx | PRESENT | `stellereum/src/rpc.rs:5214,5396` receipt/status; `stellereum/src/explorer.rs:1358,1743` `/api/tx/:hash`, `/api/tx-detail/:hash` |
| E3 | explorer block | PRESENT | `stellereum/src/rpc.rs:4506` `stell_getBlock`; `stellereum/src/explorer.rs:1893,2322` `/api/block-detail/:query` |
| L1 | light anchor | PRESENT | `stellereum/src/rpc.rs:1393` `record_finalized_header`; `stellereum/src/light_client_cli.rs:45` `light-anchor`; `light_cli_tests.rs:127` anchor_show |
| L2 | light follow | PRESENT | `stellereum/src/bootstrap.rs:14` 4-stage bootstrap; `light_client_cli.rs:46` verify/rotate; FEATURES `light-rotation`, `light-e2e` GREEN |
| L3 | light prove | PRESENT | `stellereum/src/rpc.rs:3393,3626` `stell_getProof`/`stell_getArchiveProof`; FEATURES `light-client` 18 passed GREEN |

## 2. Blockers (names only)

1. `pentest_batches_are_refused_loudly` RED — batch now served, spec/doc still says refused.
2. Public faucet captcha optional-by-default (`CaptchaConfig::Disabled` valid) — IP-throttle-only public faucet.

## 3. GAP detail (severity + missing layer)

- **Blocker / ops-spec — batch semantics flip.** `stellereum/tests/pentest_net_api_tests.rs:408`
  expects `-32600` for batch arrays; node now answers `result 0x2a` (reproduced:
  12 passed / 1 failed, matches `FEATURES.md:107` RED). Either the serving change
  is an unreviewed regression, or the pentest doc (`docs/PENTEST_NET_API.md:35`
  probe 12) + test are stale. Missing: lead decision (code revert or spec update),
  not new crypto. Until decided, matrix cannot be 100% green and clients cannot
  rely on documented batch behavior.
- **Blocker / ops — faucet anti-sybil insufficient for PUBLIC as-configured.**
  Honest report: default is IP throttle 20/hr (`rpc.rs:332`) + lifetime cap per
  address + optional Turnstile (`turnstile.rs:80` `Disabled` = both keys unset keeps
  working; `:261` warns "relying on IP throttle alone"). Rotating IPs/addresses
  defeat both (code itself notes it: `rpc.rs:324` "rotating addresses…draining").
  XFF-spoofing is handled (`client_ip.rs:22` rightmost-secure-default, F8 test),
  but that does not stop a botnet. Missing: ops — require `CaptchaConfig::Enabled`
  (both `STELL_TURNSTILE_*` keys) for the public faucet + per-node faucet rate
  dashboards; no code change needed, but as-shipped default is NOT public-safe.
- **Major / live-proof — no external-validator join ever demonstrated.**
  All election/jail/redelegate proofs are unit/local (`validator_ux_tests.rs:53…`,
  3-node local cluster in pentest docs). Missing: live-proof — one real external
  operator keygen→bond→elected→reward→unbond on a public-height chain, with
  explorer-visible evidence (lead's own queue item 5 asks for a visible
  slashing drill — same gap class).
- **Major / ops-known — PENTEST_NET_API M1+M2 documented-wontfix.**
  `docs/PENTEST_NET_API.md:40` STOP/CONT round-skew needs operator restart
  (~150 s heal); `:44` per-IP strike-ban hits shared-IP (loopback) blast radius.
  Both fail-safe, but M1 is a public-testnet liveness story needing a runbook entry.
- **Minor / docs — quickstart has pasted-output TODOs.**
  `docs/site/01-quickstart.md:89` "TODO (live output)… paste the real JSON".
  Newcomer genesis story itself EXISTS (genesis funds faucet
  `stellereum/src/main.rs:7814`; `GENESIS_FAUCET_BALANCE`, `:1095`; drip→transfer→deploy
  in quickstart `:76`); the TODOs just leave it unproven in docs.

## 4. Cross-cutting audits

- **Error messages: PASS (human-readable).** `rpc.rs:7419` `method not found: <name>`
  (truncated, bounded); `:6326` `missing or invalid address`; `:2711` `invalid
  address: <snipped>`; `staking.rs:410` `unbonding cooldown has not elapsed`;
  `bootstrap.rs:138` loud REFUSING with exact env fix; `turnstile.rs:267` 503 +
  startup WARN on half-configured captcha. No silent fails found.
- **CLI help: PRESENT (structure-verified).** clap derive
  (`stell-wallet/src/main.rs:29`, `stellereum/src/main.rs:6638` about-string),
  subcommands `Run`/`node-bootstrap` (`main.rs:6648,6662`), wallet
  stake/delegate/unbond/claim (`main.rs:878,902,1845…2021`), light
  anchor/verify/rotate (`light_client_cli.rs:45`). Full `--help` output run: NOT done (see UNVERIFIED).
- **RPC coverage vs journeys: NO orphan step.** Every write path resolves to an RPC:
  stake/delegate/unbond/claim via `stell_nativeApi` (`native_api.rs:191…226`) +
  `stell_sendRawTransaction` (`rpc.rs:5910`); reads via `stell_get*`; proofs via
  `stell_getProof`/`stell_getArchiveProof`; faucet via `stell_faucet`. No journey
  step lacks a method.
- **Genesis-for-newcomer story: COHERENT, operator-owned.** Single-shard canon +
  faucet-keyed genesis (`main.rs:7775`, `:7814`); observer bootstrap demands clean
  dir + `STELL_FAUCET_KEY` match (`bootstrap.rs:66,94`). First coins = genesis-funded
  faucet account → `stell_faucet` drip (10 STELL, 1000 lifetime cap per quickstart).
  Implication the lead doc accepts: testnet launch is a coordinated genesis with a
  published faucet key + chain id, not permissionless mining.

## 5. UNVERIFIED (count: 5)

1. Full `--help` text of every CLI (structure only, never executed).
2. Explorer HTML rendering in a browser (routes + tests only).
3. Real public DNS seeds / chain-id / faucet URL values (none published yet).
4. `H` cutoff constants' chosen values (lead picks pre-public; code has placeholders).
5. Wallet-against-public-endpoint run (only local `wallet-live-node` GREEN).

## Verdict

Feature set is **NOT 100% for a PUBLIC testnet**: 17/17 journey steps have
code+tests, but 2 Blockers (batch-behavior decision; mandatory-captcha ops gate)
plus 2 Major live-proof/ops items stand in the way. Everything else is
Minor/docs. Nothing requires new cryptography — matches the lead's ~95% call.
