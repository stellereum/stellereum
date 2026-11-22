# Testnet / Developer Experience Comparison — Cosmos vs Solana vs Ethereum vs Stellereum (today)

Date: 2026-11-01. Scope: research + one docs file. No live nodes touched, no live
endpoints curled, no builds/tests run. External facts via web search (2026).
Internal facts from repo reads only (file:line/command refs). This doc creates no
code and changes no behavior.

## 1. External baselines (what "good" looks like on day 1)

### 1.1 Cosmos (Hub public testnet, `provider`)

| Dimension | Testnet UX today |
| --- | --- |
| Faucet | Web faucet `faucet.polypore.xyz` + Discord `#faucet` channel. Paste `cosmos1…` address, get test ATOM. Coordinator-controlled faucet holds >100M liquid tokens (cosmos/testnets README). |
| Wallet CLI | `gaiad keys add <name> --keyring-backend test` (mnemonic printed), `gaiad keys show -a`, `gaiad q bank balances <addr>`, `gaiad q tx <txhash>`. Single binary = node + wallet + query. Backends: `os`/`file`/`test`/`memory`. |
| Explorer | Mintscan, `explorer.polypore.xyz/provider`, ping.pub / BigDipper (self-hostable), testnet.itrocket.net. Address/tx/validator/gov/IBC views. |
| Contract SDK + deploy | CosmWasm (`wasmd`): `cargo generate` template → `cargo schema` → `wasmd tx wasm store <wasm> --gas auto` → `instantiate` → `execute`/`query`. EVM side (Cosmos EVM): Hardhat/Foundry/ethers/viem/wagmi work unchanged, point at RPC + chain ID. |
| RPC docs | `docs.cosmos.network`: version-stamped pages ("checked 2026-10-15", gaia v29.0.0-rc0), per-command verify boxes, `abci_info`/`status` curl checks, state-sync trust-height runbooks. |
| Staking/delegation | `gaiad tx staking delegate <valoper> <amount>uatom --gas auto --gas-adjustment 1.5 --gas-prices 0.005uatom` → txhash in ~6s; `q staking delegations`, `q distribution rewards`, `redelegate`/`unbond` (21-day `unbonding_time`, 180-seat set, 5% min commission — all queryable via `q staking params`). Delegator CLI guide + FAQ are separate docs. |
| Monitoring/status | Node: `gaiad status` (`catching_up:false` vs explorer height), OpenTelemetry/Prometheus telemetry, `snapshots.polypore.xyz`. No single "status.cosmos" page; network health = explorers + validator uptime + forum/Discord. |
| Incident comms | Testnet README (version, next upgrade, endpoints, join scripts) + Discord `#testnet` channel + forum (Hub Unit reports, e.g. Jan-2026 incident + v25.3.x releases) + governance upgrade-plan queries (`q upgrade plan`). Cosmovisor automates binary swap at upgrade height. |

Sources: `docs.cosmos.network/hub` join-testnet / delegator-cli-guide / delegator-faq /
tool-guide, `github.com/cosmos/testnets`, forum.cosmos.network Hub Unit Jan-2026.

### 1.2 Solana (devnet/testnet)

| Dimension | Testnet UX today |
| --- | --- |
| Faucet | **Three programmatic paths + web**: `solana airdrop 2 [--url devnet]` (CLI), `faucet.solana.com` (web, max 2 req / 8h, GitHub-gated higher limits), RPC-provider faucets (Helius/QuickNode/Triton via own RPC URL), PoW faucet (`cargo install devnet-pow; devnet-pow mine`), plus `solana-test-validator` for unlimited local SOL. AI agents are explicitly routed to CLI/PoW/local, not the web form. |
| Wallet CLI | `solana config set --url devnet --keypair <file>` once; then `solana address/balance/account/transfer <addr> 0.1/confirm <sig>/transaction-history/logs`, `--output json` for scripting, `solana-keygen new`. One mental model: cluster URL + signer + commitment. |
| Explorer | `explorer.solana.com` (cluster switcher: mainnet/devnet/testnet/custom RPC), Solscan, SolanaFM, Helius Orb, Solana Beach. Slot/block/tx/program/account/log views. |
| Contract SDK + deploy | `solana program deploy <so>` / `program show --buffers`, Anchor (`anchor build/test/deploy`, IDL), Playground (browser, zero-install: wallet + `solana airdrop 5` in terminal). Token: `spl-token` CLI quickstart. |
| RPC docs | `solana.com/docs`: clusters page (endpoints, gossip entrypoints, devnet rate limits: 100 req/10s/IP, 40/single-RPC, 40 conns, 100MB/30s), CLI reference per Agave release (`solana --version`, `--help` per command), cookbook airdrop/faucet page. |
| Staking/delegation | `solana-keygen new --outfile stake.json; solana create-stake-account stake.json 1; solana delegate-stake stake.json <vote-addr>`; `stake-account/stakes/validators/stake-history/stake-minimum-delegation`; `deactivate-stake` (epoch-boundary) → `withdraw-stake`. Third-party validator pages (Marinade Explore, slashr) add take-rate/APY/incident-per-epoch track records. |
| Monitoring/status | `status.solana.com` + incident history with SMS/webhook subscriptions; per-node `catchup/cluster-version/epoch-info/validators` (skip-rate, commission, version summary). |
| Incident comms | Status page is the contract: incident declared → updated → resolved, with history. Validators app / slashr feed mirror downtime/slashing/commission-change events per epoch. |

Sources: `solana.com/developers/cookbook/development/airdrops-and-faucets`,
`faucet.solana.com`, `solana.com/docs/references/clusters`,
`solana.com/docs/references/solana-cli`, `solana.com/docs/intro/quick-start`,
`status.solana.com/history`, Marinade Explore, slashr.dev.

### 1.3 Ethereum (Sepolia / Holesky / Hoodi)

| Dimension | Testnet UX today |
| --- | --- |
| Faucet | Multi-vendor: Google Cloud faucet (Sepolia+Holesky, Google-account rate limit, optional 0.001 mainnet-ETH anti-Sybil), Chainstack faucet (no social login, 1 top-up/24h/address, auto-claim schedules, MCP `request_testnet_funds` for agents), ETHGlobal (0.05 ETH × 13+ chains, chain-ID table), Superblock (0.1 ETH Sepolia/Holesky, 1/day). Pattern: **faucet = web form + tx-hash you can follow on any explorer**. |
| Wallet CLI | No single canonical CLI; the wallet is MetaMask/Rabby + `cast` (Foundry) / `hardhat` console. Chain add = name + RPC URL + chain ID + currency symbol. Testnet keys strictly separated (`.env`, keystore plugin, CI temp keys). |
| Explorer | Etherscan family (`sepolia.etherscan.io`): address/tx/block/token/contract-source-verify, plus client-diverse RPCs behind it. |
| Contract SDK + deploy | **Two paved roads**: Hardhat Ignition (`npx hardhat init --typescript`, `networks.sepolia {url, chainId:11155111}`, `hardhat-keystore`, `run scripts/deploy.ts --network sepolia`, `verify --network sepolia`) and Foundry (`forge init`, `foundry.toml [rpc_endpoints]`, `forge create --rpc-url … --private-key …`, `forge verify-contract --chain sepolia`). OpenZeppelin templates, EIP-1559 fee knobs, RBF/nonce runbooks. |
| RPC docs | Execution+consensus API split; Alchemy/Chainstack/Google Blockchain RPC (100 rps, 1M req/day preview) with project-ID endpoints; `chainId` per network is the join key (Sepolia 11155111, Holesky 17000, Hoodi new). |
| Staking/delegation | Staking Launchpad per network (Holesky/Hoodi launchpads: deposit → validator lifecycle); Lido-style deployed-address registries (`deployed-contracts/sepolia.md`, now deprecated → Hoodi). Validator testing moved Holesky→Hoodi (exit-queue lesson: Holesky exits ≈1y to drain); app testing stays Sepolia (EOL ~2026-09-30, replacement ~2026-03 per EF blog). |
| Monitoring/status | No single L1 status page; health = client diversity + explorers + provider status pages (Alchemy/QuickNode/Google) + Grafana/CloudWatch on own RPC error rates. |
| Incident comms | EF blog posts (e.g. 2025-03-18 Hoodi/Holesky Pectra post-mortem), client release notes, network-upgrade epoch announcements (Hoodi Pectra epoch 2048). Protocol lesson: **testnet purpose is labeled** (Hoodi=validators, Sepolia=apps) so devs pick correctly. |

Sources: `cloud.google.com/application/web3/faucet/ethereum/sepolia`,
`docs.chainstack.com/docs/faucets`, `ethglobal.com/faucet`, `blog.ethereum.org/2025/03/18/hoodi-holesky`,
`hardhat.org/docs/guides/deployment`, Lido `deployed-contracts/sepolia.md`.

## 2. OUR surface today (what exists in this repo — same shape)

> Conventions: `STELL_RPC_URL` default `https://rpc.stellereum.org` is aspirational
> until a public node exists; loopback today is `http://127.0.0.1:8545`.
> Amounts: 1 STELL = 10⁹ nano-STELL; token amounts are raw base units (u64).

| Dimension | What exists TODAY (file:line/command) |
| --- | --- |
| Faucet | Three disjoint paths, all operator-gated. (a) Auth RPC `stell_faucet {address, token, amount?}` — `stellereum/src/rpc.rs:4557` dispatch, fail-closed on missing `STELL_FAUCET_TOKEN` (`rpc.rs:48-49,161-165`). (b) Explorer token gate `POST /api/faucet/:address` — `stellereum/src/explorer.rs:549-684` (token via `?token=`/`?apiKey=`/auth header, shard-scope check, per-IP hourly throttle, 10 STELL default drip / 1000 STELL lifetime cap per `docs/site/01-quickstart.md:76-94`). (c) Public widget `POST /api/faucet-public/:address` — `explorer.rs:729-884`: fixed **5 STELL / 45-min per-address cooldown**, Turnstile (`STELL_TURNSTILE_*`, fail-closed on misconfig/unreachable siteverify), single-file HTML form (`explorer.rs:371-443`, `render_index`). Wallet: `stell faucet [amount]` — `stell-wallet/src/main.rs:136-140,1653-1687`, via `LightClient::faucet_drip_rpc` (`stell-wallet/src/client.rs:356-364` → `stell-wallet/src/rpc.rs:855-875` POSTs `stell_faucet`). No web faucet beyond a node operator's own gateway page; no GitHub/PoW/agent path; no auto-top-up. |
| Wallet CLI | `stell` (`stell-wallet/src/main.rs:30-69` globals `--wallet/--config/--rpc-url/--auth-token/--faucet-token/--timeout/--poll-interval`; `Commands` enum `:72-747`). Two modes (`stell-wallet/README.md:12-45`): local-sim (default, honest "NOT chain-finalized") vs `--rpc-url` chain-verified (SPV proofs via `stell_getBalanceSpv`/`stell_tokenBalanceSpv`, receipts polled to Pending/Confirmed/Failed/Unknown). Coverage: `new/restore/wallets/switch/receive/balance/receipt/txs` + `pay/send` (280k nano base fee) + full staking set (`stake/unbond/delegate/begin-unbond/withdraw-unbond/claim-rewards/rotate-key`, `:179-275`) + stealth/shielded (`stealth-pay/scan/spend`, `confidential-shield/balance/unshield/pay`) + STS tokens (`token-balance/send/approve/create/resolve/list`) + `session`/`aa`/`trade/book/buy/sell/cancel` + `sign/verify/sign-typed-data/verify-typed-data` + `pq-address/pq-generate/pq-transfer/pq-status` + `console` REPL. Sharp edges (documented in-repo): the staking-lifecycle commands now sign with the wallet's PQ key (`pq_keypair_for_keystore`, `main.rs:876-900`) and refuse a classical `ed25519` or `mldsa44` keystore; local `book/buy/sell` and `mint` are simulations, not chain writes (`README.md:153-193`); token amounts have no decimals handling; address is hex-or-Stl57. |
| Block explorer | One self-contained HTML page + read-only JSON API served by the node gateway (`stellereum/src/explorer.rs:1-10`; routes `:1486-1517`). Pages: `/` (stats + balance/SPV lookup + 5-STELL faucet form + recent blocks). Endpoints: `GET /api/stats` (`:485`), `/api/version` (`:1374`), `/api/blocks` (`:522`), `/api/balance/:address` (`:886`), `/api/spv/:address` (`:899`), `/api/contracts?limit&offset` (`:920`, default 100/max 1000), `/api/tx/:hash` (`:1109`, mempool-rendered or `receipt-only`, unauthenticated pending bodies redacted to hash/nonce/status), `/api/confidential/:commitment` (`:1186`), `/events` SSE, `/health`+`/healthz` (`:1198-1213`), `/readyz` (`:1219`, `no_peers/no_finality/finality_stalled/height_zero/height_stalled`), `/metrics` Prometheus (`:1266+`, `stell_ready` gauge). Per-IP 30 req/s limiter (`:26-44`). Richer UI lives out-of-tree: `explorer-site/` (npm workspace, backend+frontend dirs). No hosted public explorer URL in-repo; no tx search by sender, no validator/commission pages, no token-holder pages, no contract source verification. |
| Contract SDK + deploy | Minimal canonical SDK (`stellereum-sdk/src/lib.rs:1-30`; guide `stellereum-sdk/README.md`): `FalconKeypair` + `TxBuilder::{transfer,contract_call,stake,unjail,gov_propose,gov_vote}` with `.nonce/.gas_limit/.base_fee/.priority_fee_per_gas/.shards/.chain_id/.identity/.sign` and `SignedTx::{to_bytes,to_hex,tx_hash,tx_hash_hex,verify,verify_with_key}`. Wire bytes = node `Transaction` bincode; chain-id bound by default (5757, `SDK_DEFAULT_CHAIN_ID`). Deploy flow: there is no `TxBuilder` deploy method today; use the node `stell_deployContract` RPC (or a raw `Op` payload). `TxBuilder::contract_call` builds `Op::call` with typed `CallArg`s. On-chain side: `stellereum-contracts/{contracts,crates/stellereum-contract-sdk}` + `crates/e2e-tests`; example WAT `contracts/sts20_token.wat`; host surface = 13 `host.*` imports (`docs/site/03-contracts.md`, `docs/specs/03_VM_AND_EXECUTION.md`). Node owner flow also has `stell_deployContract` / `stell_callContract` **previews** (token-gated, never enter the mempool) plus `stell_runGetMethod` / `stell_getEvents` (see `docs/site/01-quickstart.md:118-156`). Deliberately out of SDK scope: rewards-claim, key rotation, priority bids, session/EVM envelopes (`lib.rs:661-671`). No `forge create`/`hardhat verify` equivalent; no published-template → build → deploy → verify single path. |
| RPC docs | `docs/site/01-quickstart.md` is the 60-min loop (install → wallet → `stellereum run --config … --shard 0` → `rpc stell_faucet …` → `wallet send` → `stell_deployContract` → `stell_callContract/runGetMethod/getEvents/getTransactionReceipt`, with per-step "If it fails" boxes). Method names referenced: `stell_chainId/getBalance/getBalanceSpv/tokenBalanceSpv/sendRawTransaction/estimateFee/getTransactionReceipt/getTransactionStatus/mempoolSize/mempoolDump/signMessage/signTypedData/callContract/runGetMethod/getEvents/build_info/syncing/blockNumber/baseFee/getShards`. **Gap flag:** quickstart cites `docs/RPC.md §4` and `docs/VALIDATOR_ONBOARDING.md §0`, but `docs/` listing has no `RPC.md`/`VALIDATOR_ONBOARDING.md` (only `site/*.md`, `specs/*`, runbooks below) — authored RPC reference is missing or misplaced. RPC code is the reference instead (`stellereum/src/rpc.rs`, esp. header `:30-55` auth-token matrix + `stell_faucet` `:4557`, receipt `:5080`, `estimateFee` `:5576`, `sendRawTransaction` `:5648`). |
| Staking/delegation | Full lifecycle in wallet CLI (`main.rs:179-275`: `stake [--commission-bps]` immutable-after-bond, `delegate`, `begin-unbond` → `withdraw-unbond` after cooldown, `claim-rewards [--delegator]`, `rotate-key` atomic-move) + `docs/site/04-validators.md`. Reads: `q`-equivalents are `stell balance`, `stell receipt`, explorer `/api/*` (no dedicated `validators`/`delegations` query doc in quickstart). All lifecycle commands are PQ-signed today (`pq_keypair_for_keystore`; ed25519 keystores are refused, mldsa44 unsupported). |
| Monitoring/status | Machine-readable, operator-local: `/healthz` (cheap liveness), `/readyz` (peer/finality/height gates, env-tuned `STELL_READY_MAX_STALL_SECS/MIN_PEERS`), `/metrics` (consensus height/votes/fork counters, mempool, `stell_ready`, build info), `/api/stats` (chain_id/height/mempool/state_root/contracts + MEV sealed-share). Tools: `scripts/tools/stelops` (`src/main.rs:60-80`: `checkpoint/genesis-root/meta/doctor/diverge/clear-lock --force`, offline sled inspection, refuses on live lock) + `scripts/{doctor.sh,harness_status.sh,verify_testnet_ideal.sh,local-cluster.sh,feature_matrix.sh}` + `STATUS.md` (machine-generated). No public `status.*` page, no incident-history feed, no SMS/webhook subscriptions, no validator uptime/commission directory. |
| Incident comms | In-repo only: `STATUS.md` + `handoff/` + `docs/ROADMAP.md` + `docs/LIVE_DEMOS_RUNBOOK.md` + spec docs. No labeled testnet-purpose statement (cf. Ethereum's "Hoodi=validators, Sepolia=apps"), no upgrade-epoch announcement channel, no status-page contract, no forum/Discord runbook pointer in the quickstart. Chain halt forensics exist (`stelops diverge`, `docs/REPLAY_ANALYSIS.md`, `docs/PROPOSER_REWORK.md`) but are operator tools, not developer comms. |

## 3. Ranked gaps — what a developer needs on day 1 that we lack

Ranked by "can a stranger go from zero to first confirmed tx + first contract call
without asking a human for help". Each item names the closest thing we have so the
fix is additive, not a rewrite.

1. **No permissionless first-coins path.** Every faucet route needs an operator
   secret (`STELL_FAUCET_TOKEN` for `stell_faucet`/`POST /api/faucet/:address`;
   Turnstile + owning a gateway node for `/api/faucet-public`). Cosmos/Solana/
   Ethereum all offer at least one no-relationship drip (web form, `solana airdrop`,
   multi-vendor faucets, PoW fallback). **Day-1 ask:** one public testnet gateway
   with the existing 5-STELL/45-min Turnstile faucet on, plus documented CLI
   equivalent (`stell --rpc-url <public> faucet` without a token) and rate-limit
   headers in the 429 body. Nothing to invent: `explorer.rs:729-884` already is
   the widget.
2. **No single-command network join.** Reference UX is `solana config set --url
   devnet` / `gaiad --home ~/.gaia-testnet` + one faucet call. Ours is: build from
   source (`cargo build --bin stellereum`), choose local-sim vs `--rpc-url`,
   export two tokens, learn `-1:<hex>` masterchain vs bare workchain addressing
   (`01-quickstart.md:86-94`), tune `--timeout/--poll-interval`. **Day-1 ask:** a
   `networks.toml` (or `--network testnet` flag) pinning rpc/explorer/faucet/
   chain-id (5757) + a 10-line join runbook that ends in `stell balance` green.
3. **Explorer answers machines, not humans.** We expose the right JSON
   (`/api/stats/blocks/balance/spv/tx/contracts`, `/events`, `/metrics`) but the
   human page is one static file with no address history, no validator set/
   commission view, no token-holder view, no contract source/ABI view, no
   cluster switcher. Solana/Etherscan/Mintscan day-1 loop is "paste hash → see
   status → click through". **Day-1 ask:** promote `explorer-site/` (or freeze
   it) and commit the gateway page to: tx lookup with status/height/fee,
   address page with balance+nonce+recent txs, validator list, contract page
   with verify-via-ABI. Until then, document the five curl one-liners.
4. **Contract deploy loop is expert-only.** Solana has `program deploy` + Anchor +
   Playground; Ethereum has Ignition/Foundry + verify; Cosmos has `store →
   instantiate → execute` templates. Ours requires hand-rolled WAT against 13
   `host.*` imports, hex-of-wasm JSON fields, and predicting deploy addresses
   from nonces — with no `verify` step and SDK gaps (no claim/rotate/priority/
   session envelopes). **Day-1 ask:** one template (STS-20), one `deploy`
   wrapper (wasm file in → address out), one `call` wrapper (method+args in →
   receipt out), and a verify story (publish ABI → explorer renders it).
5. **No public health contract.** We have better machine signals than most
   (`/readyz` failure reasons, `stell_ready`, stelops forensics) but zero
   developer-facing status: no `status.*` page, no incident history, no labeled
   network purpose ("this testnet is for X, resets on Y"), no upgrade-epoch
   announcements, and the quickstart's cited `docs/RPC.md` /
   `docs/VALIDATOR_ONBOARDING.md` don't exist under `docs/`. **Day-1 ask:**
   (a) restore or retarget those two references; (b) publish a minimal status
   page backed by the existing `/readyz`+`/metrics`; (c) label the testnet's
   purpose + EOL/reset policy like Ethereum does, so devs know what they're
   building on.

### Also-noted (not top-5, still day-1 friction)

- Staking split-brain: `stake`/`pay` have PQ paths but `unbond/delegate/
  begin-unbond/withdraw-unbond/claim-rewards/rotate-key` refuse PQ keystores
  (`main.rs:883-892`) — a PQ-first dev hits a wall mid-lifecycle.
- Amount UX: STELL decimal strings vs STS raw base units vs nano-STELL flags
  across commands; no shared "how amounts work" table.
- `stell trade/book/buy/sell` and `stell mint` simulate locally; the names read
  like chain writes (README warns, but day-1 users will misread).
- Address formats (hex vs `Stl57…`) are accepted inconsistently across surfaces;
  explorers elsewhere accept one and display both.
- `stelops` is excellent forensics but stop-the-node-only by design
  (`src/main.rs:22-30`); there is no read-only live counterpart for devs
  beyond `/api/*`.
