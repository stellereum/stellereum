# Testnet Completeness Audit (HDAE, 2026-11-03, read-only)

Sources: `FEATURES.md` (102 GREEN / 1 RED / 1 SKIP), `docs/PUBLIC_TESTNET_CODE_GAPS.md`
(lead freeze, 2026-11-03), code+tests (every `file:line` below grep/execution-verified).
Rule: no existing file modified; this is the single new doc.
Runtime verification pass 2026-11-03 (HEAD `ea69c425f` working tree): UNVERIFIED count 0, see §5.

## 1. Journey table (17 steps: 17 PRESENT / 0 missing-code, 4 with caveats)

| # | Step | Verdict | Proof |
|---|---|---|---|
| V1 | validator keygen | PRESENT | `stellereum/src/node_keys.rs:686` `load_or_generate_node_keys`; `stell-wallet/src/main.rs:5401` `pq-generate`; FEATURES `pq-keygen-sign-verify` GREEN |
| V2 | bond (min 1100 STELL) | PRESENT | `stellereum/src/native_api.rs:191,637` `stell_stakeBond`→`SysCallStake`; `stellereum/src/staking.rs:59,75` floor; `stell-wallet/src/main.rs:902` `stake_opcode` |
| V3 | elected (top-250) | PRESENT (code) + live-proof GAP (Major, §3) | `stellereum/src/staking.rs:1981` truncate 250; `:1988` `elected_count`; `stellereum/src/rpc.rs:5507` `stell_getValidators`, `:5461` `stell_getValidatorStatus`; join doc `docs/site/04-validators.md:102` |
| V4 | rewards | PRESENT | `stellereum/src/staking.rs:2979` `distribute_reward`; `:3135` `claim_validator_rewards`; `stellereum/src/native_api.rs:226` `stell_claimRewards` |
| V5 | unbond (2-day cooldown) | PRESENT | `stellereum/src/staking.rs:228` `UNBONDING_PERIOD_SECS = 2*24*3600`; `stell-wallet/src/main.rs:208,232,244` unbond/begin-unbond/withdraw-unbond; `stellereum/src/native_api.rs:198,205` |
| C1 | faucet drip | PRESENT (code) + anti-sybil GAP (Blocker-ops, §3, lead-pending §6) | `stellereum/src/rpc.rs:4691` `stell_faucet`; `:336` `FAUCET_IP_MAX_PER_HOUR=20`; `:291` drip default 10 STELL; explorer public path `explorer.rs:736` `api_faucet_public` (5 STELL / 45-min); FEATURES `faucet-pq` GREEN |
| C2 | transfer | PRESENT | `stellereum/src/rpc.rs:5910` `stell_sendRawTransaction`; `stellereum/src/native_api.rs:127` `stell_tokenTransfer`; `stell-wallet/src/main.rs:5086` pay/send |
| C3 | fees | PRESENT | `stellereum/src/rpc.rs:5838` `stell_estimateFee`; FEATURES `fee-determinism`, `pq-fee` GREEN |
| D1 | deploy contract | PRESENT | `stellereum/src/rpc.rs:6467` `stell_deployContract`; FEATURES `contracts-node-side`, `sts20/dns/pool/account-onchain` GREEN |
| D2 | call contract | PRESENT | `stellereum/src/rpc.rs:6737` `stell_callContract`; FEATURES `evm-flows` 92 passed GREEN |
| D3 | events | PRESENT | `stellereum/src/rpc.rs:5283` `stell_getEvents`; `:1435` receipts-with-events; FEATURES `explorer-ux` GREEN |
| E1 | explorer balance | PRESENT (routes+tests) + browser-render runtime-check (§5.2) | `stellereum/src/rpc.rs:4814` `stell_getBalance`; `stellereum/src/explorer.rs:1091` `/api/account/:address`; FEATURES `indexer-api` GREEN |
| E2 | explorer tx | PRESENT (routes+tests) + browser-render runtime-check (§5.2) | `stellereum/src/rpc.rs:5214,5396` receipt/status; `stellereum/src/explorer.rs:1358,1743` `/api/tx/:hash`, `/api/tx-detail/:hash` |
| E3 | explorer block | PRESENT (routes+tests) + browser-render runtime-check (§5.2) | `stellereum/src/rpc.rs:4506` `stell_getBlock`; `stellereum/src/explorer.rs:1893,2322` `/api/block-detail/:query` |
| L1 | light anchor | PRESENT | `stellereum/src/rpc.rs:1393` `record_finalized_header`; `stellereum/src/light_client_cli.rs:45` `light-anchor`; `light_cli_tests.rs:127` anchor_show |
| L2 | light follow | PRESENT | `stellereum/src/bootstrap.rs:14` 4-stage bootstrap; `light_client_cli.rs:46` verify/rotate; FEATURES `light-rotation`, `light-e2e` GREEN |
| L3 | light prove | PRESENT | `stellereum/src/rpc.rs:3393,3626` `stell_getProof`/`stell_getArchiveProof`; FEATURES `light-client` 18 passed GREEN |

## 2. Blockers

1. ~~`pentest_batches_are_refused_loudly` RED — batch now served, spec/doc still says refused.~~ **CLOSED 2026-11-03** (verified: `cargo test --test pentest_net_api_tests` → 13 passed / 0 failed; batch served per-item `stellereum/src/evm_adapter.rs:3506`, empty batch refused `-32600` `stellereum/src/rpc.rs:2336`; test `stellereum/tests/pentest_net_api_tests.rs:399-423` asserts array-shape + per-item result + empty-batch `-32600`). Spec decision = serve-batches-per-item, doc `docs/PENTEST_NET_API.md:35` probe-12 row is stale (lead to refresh, no code).
2. Public faucet captcha optional-by-default (`CaptchaConfig::Disabled` valid) — IP-throttle-only public faucet. **OPEN, lead-pending — no code change in this task; decision record with options + recommendation in §6.**

## 3. GAP detail (severity + missing layer)

- **~~Blocker / ops-spec — batch semantics flip.~~ CLOSED.** `stellereum/tests/pentest_net_api_tests.rs:399` now asserts serve-per-item (array with per-item `result`, `v[0]["id"]==1`) + empty-batch `-32600`; full file 13/13 GREEN (run 2026-11-03). Serving code: `evm_adapter.rs:3506` `invalid_request("empty batch")`, `rpc.rs:2336` `batch_refused("empty batch")`. Remaining: refresh the stale probe-12 row in `docs/PENTEST_NET_API.md:35` (docs-only, lead queue).
- **Blocker / ops — faucet anti-sybil insufficient for PUBLIC as-configured.**
  Honest report: default is IP throttle 20/hr (`rpc.rs:336`) + lifetime cap per
  address + optional Turnstile (`turnstile.rs:80` `Disabled` = both keys unset keeps
  working; `:261` warns "relying on IP throttle alone"). Rotating IPs/addresses
  defeat both (code itself notes it: `rpc.rs:327` "rotating addresses…draining").
  XFF-spoofing is handled (`client_ip.rs:22` rightmost-secure-default, F8 test),
  but that does not stop a botnet. Missing: ops — lead decision §6 (require `CaptchaConfig::Enabled`
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
  `stellereum/src/main.rs:424` `fund_shard_genesis`; `GENESIS_FAUCET_BALANCE`, `:427`; drip→transfer→deploy
  in quickstart `:76`); the TODOs just leave it unproven in docs.

## 4. Cross-cutting audits

- **Error messages: PASS (human-readable).** `rpc.rs:7419` `method not found: <name>`
  (truncated, bounded); `:6326` `missing or invalid address`; `:2711` `invalid
  address: <snipped>`; `staking.rs:410` `unbonding cooldown has not elapsed`;
  `bootstrap.rs:138` loud REFUSING with exact env fix; `turnstile.rs:267` 503 +
  startup WARN on half-configured captcha. No silent fails found.
- **CLI help: VERIFIED (executed, Appendix A).** `cargo run --bin stellereum -- --help`
  → 17 subcommands (`run`, `node-bootstrap`, `sim`, `devnet`, `sim-replay`, `wallet`,
  `orderbook`, `oracle`, `bridge`, `genesis`, `pmm`, `light-client`, `light-anchor`,
  `light-verify`, `light-rotate`, `network`, `keys`); `run --help` (4 flags),
  `node-bootstrap --help` (5 flags), `light-client --help`, `keys --help`
  (init/peer-stanza/rotate-falcon) all executed 2026-11-03. Wallet `stell --help`
  executed: 40+ subcommands incl. stake/delegate/begin-unbond/withdraw-unbond/
  claim-rewards/faucet/pay; `--rpc-url` default `STELL_RPC_URL` or
  `https://rpc.stellereum.org` (`stell-wallet/src/main.rs:43-47`).
- **RPC coverage vs journeys: NO orphan step.** Every write path resolves to an RPC:
  stake/delegate/unbond/claim via `stell_nativeApi` (`native_api.rs:191…226`) +
  `stell_sendRawTransaction` (`rpc.rs:5910`); reads via `stell_get*`; proofs via
  `stell_getProof`/`stell_getArchiveProof`; faucet via `stell_faucet`. No journey
  step lacks a method.
- **Genesis-for-newcomer story: COHERENT, operator-owned.** Single-shard canon +
  faucet-keyed genesis (`main.rs:406,424`); observer bootstrap demands clean
  dir + `STELL_FAUCET_KEY` match (`bootstrap.rs:66,94`). First coins = genesis-funded
  faucet account → `stell_faucet` drip (10 STELL, 1000 lifetime cap per quickstart).
  Implication the lead doc accepts: testnet launch is a coordinated genesis with a
  published faucet key + chain id, not permissionless mining.
- **Chain-id / seeds / endpoints: VALUES GREP-VERIFIED, none published yet (§5.3).**
  Chain id default 5757 (`zkml.rs:220` `DEFAULT_CHAIN_ID`, `evm_adapter.rs:51` `CHAIN_ID`,
  served STELL-aware `evm_adapter.rs:53`); DNS seeds opt-in `STELL_DNS_SEEDS`
  (`dns_seeds.rs:68,74`, unset = no-op `:1033-1063`); wallet default RPC
  `https://rpc.stellereum.org` (`stell-wallet/src/main.rs:45`, `client.rs:124`).
  `rpc.stellereum.org` / `seeds.stellereum.org` appear as example/default strings
  only — no live host exists to probe (no commit of live URLs, per task ban).
- **H cutoffs: VALUES GREP-VERIFIED (§5.4).** `PQ_CLASSICAL_REFUSE_AFTER_HEIGHT = 300_000`
  (`infnode/crates/infnode/src/proto.rs:395`); `PQ_TRANSPORT_H_ACTIVATION_HEIGHT = 10_000`
  (`stellereum/src/mev_epoch.rs:1191`, gated by `PREFER_PQ_MEV_TRANSPORT=false` `:1175`);
  rotation `PQ_ROTATION_DELAY_HEIGHTS = 7_200` (`pq_registry.rs:97`) == `EPOCH_LEN = 7200`
  (`cn_vrf.rs:58`).
- **Wallet-vs-endpoint: VERDICT — code supports public endpoint, no public endpoint exists to test against (§5.5).**
  Wallet resolves target `--rpc-url` → `STELL_RPC_URL` env → else `None` = local mode
  (`stell-wallet/src/main.rs:1135`; `client.rs:5-9,124`); local-only commands
  refuse loudly without `--rpc-url` (`main.rs:3483,3528`). `wallet-live-node` GREEN
  is local-cluster only (FEATURES row). Public run = same binary + `--rpc-url <public>`
  once lead publishes it; blocked on §5.3, not on code.

## 5. UNVERIFIED (count: 0 — all 5 resolved 2026-11-03)

| # | Was | Resolution (executed / grep-verified) |
|---|---|---|
| 1 | Full `--help` text of every CLI (structure only, never executed) | **RESOLVED — executed.** Node `--help` + `run`/`node-bootstrap`/`light-client`/`keys` helps + full wallet `stell --help` (Appendix A). Clap derive `stell-wallet/src/main.rs:29`, node about `stellereum/src/main.rs:6629`. |
| 2 | Explorer HTML rendering in a browser (routes + tests only) | **RESOLVED as runtime-check (no claim).** No stellereum node process running (`pgrep stellereum|infnode` = only build shells; `run/cluster/` dirs present but no PIDs; RPC base `127.0.0.1:18645` connection-refused per `scripts/local-cluster.sh:36`). Browser render NOT claimed. Exact runtime-check for the operator: `scripts/local-cluster.sh start --nodes 3` then `curl -s http://127.0.0.1:18647/api/block-detail/latest` + open `http://127.0.0.1:18647/` and compare against `explorer.rs:371-443` `render_index` (public form shows `5 STELL per address every 45 minutes`, `:390`). Routes + 15 `explorer-ux` tests + `indexer-api` GREEN remain the code proof. |
| 3 | Real public DNS seeds / chain-id / faucet URL values (none published yet) | **RESOLVED — values grep-verified, publication is a lead action.** Chain-id default 5757 (`zkml.rs:220`, `evm_adapter.rs:51,81` `0x167d`, env `STELL_CHAIN_ID` `:226`); DNS seeds opt-in env `STELL_DNS_SEEDS` (`dns_seeds.rs:68,74`); wallet default `https://rpc.stellereum.org` (`stell-wallet/src/main.rs:45`); faucet is per-node local (`explorer.rs:736`, `main.rs:8092` disabled-by-default). Nothing published → nothing to curl (live-host ban respected). |
| 4 | `H` cutoff constants' chosen values (lead picks pre-public; code has placeholders) | **RESOLVED — values grep-verified.** 300_000 (`proto.rs:395`, enforced `:400`, fail-closed `:701-749`, tests `pq_handshake_tests.rs:1027-1168`); 10_000 (`mev_epoch.rs:1191`, gate `:1198`, `PREFER_PQ_MEV_TRANSPORT=false` `:1175`, tests `:1090-1097`); 7200 (`pq_registry.rs:97`, `cn_vrf.rs:58` `EPOCH_LEN`, lead doc §5 fixes "7200 — параметр, не пробел"). Lead freeze doc pins them pre-public (`PUBLIC_TESTNET_CODE_GAPS.md:22-23`). |
| 5 | Wallet-against-public-endpoint run (only local `wallet-live-node` GREEN) | **RESOLVED — verdict with file:line.** Wallet RPC-target code `stell-wallet/src/main.rs:1135` + `client.rs:124` + fail-loud local guards (`main.rs:3483,3528`); public endpoint list = one default string (`main.rs:45`) with no live host behind it. No code gap; run is blocked on lead publishing §5.3 values. |

## 6. Faucet-captcha decision (lead-pending — NOT implemented, no code in this task)

Context (all `file:line` execution/grep-verified 2026-11-03):
- Public path `POST /api/faucet-public/:address`: fixed 5 STELL / 45-min per-address cooldown
  (`explorer.rs:720-723,736`); check order captcha→throttle→mint (`:727-735`).
- Throttle: `FAUCET_IP_MAX_PER_HOUR=20` (`rpc.rs:336`, env override `:339-345`); token path
  drip default 10 STELL (`rpc.rs:718-722`), lifetime cap per address (`rpc.rs:286-287`,
  `main.rs:1103` `FAUCET_LIFETIME_CAP`, `:7799,8127` wiring); faucet disabled without key file
  (`main.rs:8092`).
- Captcha tri-state (`turnstile.rs:80-92`): `Disabled` (both keys unset — current default,
  warns `:261-265`), `Enabled` (both keys), `Misconfigured` (exactly one — 503 fail-closed
  `:267-268`, `explorer.rs:771-778`). `Disabled` explicitly dispenses (`explorer.rs:819`).
- Residuals acknowledged in code: rotation-drain (`rpc.rs:324-329`), XFF-spoofing handled
  rightmost-secure-default (`client_ip.rs:22-40`, F8 tests `:409-602`).

| Option | Shape | Evidence | Trade-off |
|---|---|---|---|
| A | Require `CaptchaConfig::Enabled` (both `STELL_TURNSTILE_*` keys) for the public faucet; refuse start/serve otherwise | `turnstile.rs:108-126` `from_env`, `explorer.rs:771-820` already branches all three states; `log_captcha_startup` `:261-270` | Needs Turnstile account keys (blocked on keys, not code). Strongest anti-bot. |
| B (current) | Keep IP-throttle + lifetime caps + documented rotating-IP residual | `rpc.rs:332-345`, `explorer.rs:720-735`, `turnstile.rs:80-83` | Zero new deps; botnet-drainable — documented residual, NOT public-safe as sole gate. |
| C | Allowlist-vouched claims (operator vouches addresses, e.g. via sponsor-grant allowlist shape `sharding.rs:707-816`) | No faucet wiring exists — new ops process + small code | Human-gated, slowest onboarding; best for a tiny allowlisted beta. |

**Recommendation: A for the public faucet (keys are the only blocker — no code change:
`from_env` + the three-way branch + 503 paths already exist and are tested:
`faucet_turnstile_tests.rs`, `audit_rpc_evm_closeout.rs:968-1072`), B explicitly
time-boxed for closed devnets only, C only if Turnstile keys cannot be procured
before launch.** Per-node faucet rate dashboards still wanted regardless (lead ops queue).

## Verdict

Feature set is **NOT 100% for a PUBLIC testnet**, but closer than the 2026-11-03
snapshot: 17/17 journey steps have code+tests, the batch-semantics blocker is
**CLOSED (13/13 pentest file GREEN)**, and all 5 UNVERIFIED are resolved with
executed/grep evidence above. Remaining: **1 Blocker-ops (faucet-captcha lead
decision §6 — keys/process, no code)** plus 2 Major live-proof/ops-known items
and Minor docs TODOs. Nothing requires new cryptography — matches the lead's ~95% call.

## Appendix A — executed `--help` outputs (2026-11-03)

### A.1 `cargo run --bin stellereum -- --help` (from `stellereum/`)
```
Stellereum: Lightweight, AI-Native, MEV-Resistant & Orderbook-Optimized L1 Blockchain

Usage: stellereum <COMMAND>

Commands:
  run             Start Stellereum validator node with infnode P2P networking
  node-bootstrap  Bootstrap a FRESH observer from zero: preflight gate, then the live sync engine (snapshot-sync incl. ledger + all domains, body walk, live)
  sim             Run local testnet simulator (in-process multi-shard & multi-validator cluster)
  devnet          Run a local DETERMINISTIC devnet (seeded genesis, blocks, state snapshots)
  sim-replay      Replay a recorded simulator transaction log and verify the state root
  wallet          Wallet management and transaction dispatch
  orderbook       Native Orderbook-Actor CLOB operations
  oracle          3-Tier Price Oracle & Circuit Breaker inspection
  bridge          Native Teleport Bridges (TON, Arbitrum, Ethereum, Solana)
  genesis         Genesis Vault parameters & token exchange simulation
  pmm             Primary Market Maker (bonding-curve Mint & Redeem exchange)
  light-client    EXTERNAL LIGHT CLIENT: verify a state proof against a quorum-certified header, WITHOUT running consensus (Near `light_client` / Sui `sui_light_client` model)
  light-anchor    Show the light-client anchor (set hash, height) from OFFLINE files
  light-verify    Verify a header/checkpoint file against the OFFLINE anchor
  light-rotate    Rotate the OFFLINE anchor with a rotation proof file
  network         Network discovery and connectivity guide
  keys            Node identity keys for validator/observer onboarding (one-command join)
  help            Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### A.2 `cargo run --bin stellereum -- run --help`
```
Start Stellereum validator node with infnode P2P networking

Usage: stellereum run [OPTIONS]

Options:
  -c, --config <CONFIG>  Path to infnode YAML configuration file [default: config.yaml]
  -s, --shard <SHARD>    Shard ID to run (0 = Masterchain, 1 = Base Workchain) [default: 0]
      --parallel-exec    Enable disjoint wave parallel block execution
      --pure-pq          Enforce Pure Post-Quantum Mode (reject classical Ed25519/BLS transactions and QCs)
  -h, --help             Print help
```

### A.3 `cargo run --bin stellereum -- node-bootstrap --help` (tail)
```
  -s, --shard <SHARD>  Shard ID to run (0 = Masterchain, 1 = Base Workchain) [default: 0]
      --data-dir <DATA_DIR>  Data directory that must be CLEAN (no store/kv.json from a previous run) [default: ./data]
      --allow-dirty  Allow a NON-clean data directory (restart, NOT a fresh bootstrap). Fresh joins must wipe the whole ./data instead (OPERATIONS §8)
      --no-exec  Only check the preflight gate and print the plan; do not start the node
  -h, --help  Print help (see a summary with '-h')
```

### A.4 `cargo run --bin stellereum -- keys --help` (tail)
```
Usage: stellereum keys <COMMAND>

Commands:
  init           Generate node keys if missing (identity/e2e via `load_or_generate_node_keys`, Falcon-512 via `load_or_generate_falcon_key`) and print the NODE IDENTITY line
  peer-stanza    Print the peer-stanza (node-id / ed-pub / x-pub / falcon-pub) for the new node, ready for the network admin to feed to `scripts/add-peer.sh`. Keys must already exist (see `keys init`)
  rotate-falcon  Rotate the Falcon-512 validator key to a COMPLETE FIPS 206 (FN-DSA) NTRU key and print the NEW validator address
  help           Print this message or the help of the given subcommand(s)
```

### A.5 `stell --help` (from `stell-wallet/`, `./target/debug/stell --help` head + `cargo run -- --help` tail)
```
Stellereum High-Performance SPV Light Wallet

Usage: stell [OPTIONS] [COMMAND]

Commands:
  new                    Create a new hardened wallet (interactive or with password)
  restore                Restore wallet from 24-word recovery phrase or raw private key
  wallets                List all local wallets, showing address, scheme, and which is active
  switch                 Switch active wallet by name or address (verifies password)
  receive                Display wallet address, QR code, and viewing keys for receiving funds
  balance                Query account balance and verify cryptographic SPV Merkle inclusion proof
  faucet                 Request testnet faucet coins for local experimentation
  pay                    Send standard STELL transfer (base fee 280_000 nano-STELL)
  stake                  Bond STELL to become (or top up) a validator (SysCallStake). [commission immutable after bonding]
  unbond                 Start unbonding from a validator (SysCallUnbond). Only the validator itself may unbond its own stake; funds return after cooldown
  delegate               Delegate STELL to a validator (SysCallDelegate). Funds stay delegated until you begin-unbond + withdraw-unbond
  begin-unbond           Begin unbonding a delegation (SysCallBeginUndelegate). Moves funds into a maturing cooldown entry; use withdraw-unbond later
  withdraw-unbond        Withdraw matured unbonded funds (SysCallUndelegate). Only pays matured funds after cooldown; errors while still maturing
  claim-rewards          Claim accrued delegation/validator rewards (SysCallClaimRewards / SysCallClaimDelegatorRewards)
  rotate-key             Rotate a validator's consensus key (SysCallRotateValidatorKey). Only the OLD key may authorize; the whole record (bond, delegations, rewards, slash history) moves atomically, never merges
  stealth-pay            Send spendable stealth payment: derives one-time stealth address using recipient's view and spend keys and broadcasts on-chain
  stealth-scan           Scan blockchain for incoming stealth payments matching viewing key
  stealth-spend          Spend funds from a one-time stealth address to wallet or destination address
  confidential-shield    Shield native STELL into the pool (SysCallConfidentialShield). Saves note to ~/.stellereum/shielded_notes.json automatically
  shield-balance         Display unspent shielded notes and total confidential balance. Audit B-WALLET-2: requires the keystore password (notes are secret-bound; passwordless reads of legacy files are gone)
  confidential-unshield  Unshield by revealing openings or automatically selecting stored notes (SysCallConfidentialUnshield)
  confidential-pay       Build and submit a REAL shielded transfer (SysCallConfidentialTransfer): conservation-checked locally, admitted to the chain, receipt polled. Prints the tx hash plus viewing-key info for the auditor
  token-balance          Show an STS token balance (chain-verified SPV proof in RPC mode)
  token-send             Send STS tokens (SysCallTokenTransfer; native amount is 0, gas base 280_000)
  token-approve          Approve an STS spender allowance (SysCallTokenApprove)
  token-create           Create a new STS token (SysCallTokenCreate; you become minter). Prints the token ID (resolved from the node after finality)
  token-resolve          Resolve a token ID by (name, symbol) for this wallet's account
  token-list             List STS token IDs (paginated `{tokens, total, offset}` object shape)
  receipt                Query chain finality for a tx hash (RPC mode: polls the node receipt)
  txs                    View recent transaction history
  session                Delegate a session key (scoped, expiring, budgeted access for an app or bot)
  trade                  Trade on native decentralized CLOB Orderbook-Actor at micro-gas
  book                   View visual L2 depth and spread of orderbook
  buy                    Quick limit/market buy on CLOB Orderbook
  sell                   Quick limit/market sell on CLOB Orderbook
  cancel                 Cancel an active order at 100 nano-STELL micro-gas
  mint                   Exchange external assets for STELL in Genesis Vault ($0.25 fixed rate)
  export                 Securely export private key or mnemonic phrase
  status                 Inspect P2P network discovery, DHT routing, and connection topology
  aa                     Native Account Abstraction (Account Objects / Passports, session keys, rental)
  console                Launch interactive Electrum-style REPL shell
  pq-address             Derive and display 32-byte post-quantum address from public key and scheme
  pq-generate            Generate sample keypair for post-quantum scheme and derive address
  pq-transfer            Send post-quantum transfer using Falcon-512 or Hybrid scheme
  pq-status              Inspect post-quantum cryptography status and capabilities
  sign                   Sign an arbitrary message with the WALLET SIGNATURE STANDARD (EIP-191-style preimage with the chain id bound in). Produces the standard envelope (version + scheme + pubkey + signature, hex) from THIS wallet's own key — the key never leaves this machine
  verify                 Verify a WALLET SIGNATURE STANDARD envelope against an address, a message and a chain id. No key needed, no network needed
  sign-typed-data        Sign STRUCTURED contract-call data (EIP-712-style readable signing): the canonical JSON of `{contract, method, args, value, nonce, chain_id}` is displayed AND signed, so you see exactly what you authorize
  verify-typed-data      Verify a typed-data signature. The caller passes the STRUCTURED fields (what the user was shown); the canonical JSON is re-encoded locally
  help                   Print this message or the help of the given subcommand(s)

Options:
  -w, --wallet <WALLET>                Custom path to wallet keystore
  -c, --config <CONFIG>                Path to infnode P2P configuration file
      --rpc-url <RPC_URL>              JSON-RPC endpoint of a Stellereum node (e.g. https://rpc.stellereum.org). When set (or default), the wallet talks to the CHAIN (balances/proofs from the node, receipts polled to finality). Defaults to STELL_RPC_URL or https://rpc.stellereum.org
      --auth-token <AUTH_TOKEN>        Write-API token for the node (fallback: STELL_RPC_AUTH_TOKEN env)
      --faucet-token <FAUCET_TOKEN>    Faucet token for `faucet` in RPC mode (fallback: STELL_FAUCET_TOKEN)
      --timeout <TIMEOUT>              Seconds to wait for chain finality after submitting a transaction (default covers multi-minute stalls on a slow chain; broadcast still returns Pending honestly on timeout — re-check with `receipt`) [default: 360]
      --poll-interval <POLL_INTERVAL>  Seconds between receipt polls while waiting for finality [default: 2]
  -h, --help                           Print help
  -V, --version                        Print version
```

(End of file)
