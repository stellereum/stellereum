# 01 — Architecture Overview (HDAE Phase-2, code truth)

Supersedes narrative claims in `handoff/*`; replaces `01_ARCHITECTURE_OVERVIEW.md`
(2026-10-29, no per-claim citations). Every load-bearing claim below cites
`stellereum/src/*:<line>`. Paths relative to repo root unless noted.

## 1. Crates

| Crate / workspace | Role |
|---|---|
| `stellereum` (`stellereum/Cargo.toml:2-3`, package `stellereum 0.1.0`) | Canonical node: consensus, execution, storage, RPC, P2P |
| `infnode` (`infnode/crates/infnode/src/main.rs:14,335`) | Overlay: QUIC + Ed25519 transport, DHT, mailbox; `lib.rs` + `dht.rs` + `mailbox.rs` present |
| `infmail` (`infnode/crates/infmail/src/`: `blockchain.rs`, `inbound.rs`, `web.rs`, `main.rs`) | Webmail backend on the overlay |
| `stellereum-contracts/`, `stellereum-indexer/`, `stellereum-sdk/`, `stell-wallet/`, `scripts/tools/stelops/` | Contracts+SDK, SQLite indexer, client SDK, wallet/light client, operator CLI (dirs exist; roles per `stellereum-contracts/README.md:5`, `stellereum-indexer/README.md:5`, `stellereum-sdk/SDK-README.md:1-5`, `stell-wallet/README.md:6`, `scripts/tools/stelops/Cargo.toml:4` + `src/main.rs:1-5`) |

Pinned deps (consensus-relevant): `ed25519-dalek v2` (`stellereum/Cargo.toml:13`),
`x25519-dalek v2` (`:14`), `bls12_381 v0.9` (`:41`), `argon2 0.5` (`:46`),
`wasmi 2.0.0` (`:47`), `pqcrypto-falcon 0.4.1` (`:55`, linked `src/post_quantum.rs:23`).

## 2. Module map (`stellereum/src/lib.rs:1-57`)

| Module | One-line role |
|---|---|
| `address.rs` | `Stl57` address format |
| `bls.rs` | BLS12-381 aggregate path (classical; `bls.rs:80` `BLS_IS_POST_QUANTUM=false`) |
| `bootstrap.rs`, `dns_seeds.rs` | Peer discovery / bootstrapping |
| `bridge.rs`, `bridge_adapters.rs` | Bridge limits + adapters (`bridge.rs:34-47`) |
| `cell.rs`, `chain.rs`, `chain_binding.rs` | State cells, chain store, chain-id/admission binding (`chain_binding.rs:38`) |
| `cn_vrf.rs` | CN-VRF sandbox, pure module, no consensus wiring (`cn_vrf.rs:1-4`) |
| `commitment.rs`, `mmr.rs` | Commitments, MMR epoch roots |
| `consensus.rs`, `consensus_net.rs` | BFT core + broadcast transport |
| `contract.rs`, `contract_abi.rs`, `contract_source.rs` | WASM engine, ABI, `.wat` source registry |
| `cpat2.rs` | Compressed patricia trie (exclusion proofs) |
| `crypto_privacy.rs`, `wallet_signing.rs`, `wallet.rs` | Shielded transfers, `STELL-MSGSIG-V1` (`wallet_signing.rs:50`), wallet |
| `evm_adapter.rs`, `svm.rs` | EVM compat shim (`CHAIN_ID 5757`, `evm_adapter.rs:51`); SVM execution + gas table (`svm.rs:38`) |
| `explorer.rs`, `metrics.rs`, `simulator.rs` | Explorer, metrics, deterministic sim |
| `governance.rs` | On-chain gov (quorum `GOVERNANCE_QUORUM_BPS 6666`, `governance.rs:30`) |
| `light_client*.rs` | Light client + CLI |
| `main.rs`, `runtime.rs` | Node entry, block-apply paths (`runtime.rs:6884,6894,8184`) |
| `mempool.rs` | Fee-priority admission (`mempool.rs:20-55`) |
| `mev*.rs`, `mev_epoch.rs`, `mev_v4.rs` | MEV pipelines |
| `native_api.rs`, `rpc.rs` | 35-method catalog `METHODS` (`native_api.rs:124-402`; first `stell_tokenTransfer` `:127`, last `stell_nativeApi` `:402`; prior spec's 22 superseded by recount) |
| `network.rs`, `sync.rs`, `storage.rs` | Overlay use, catch-up (`sync.rs:134,351`), persistence |
| `node_keys.rs`, `remote_signer.rs` | Key custody, remote signer |
| `oracle.rs`, `orderbook.rs`, `pmm.rs` | Price feeds (`oracle.rs:10-34`), CLOB (`orderbook.rs:9-11`), PMM (`pmm.rs:30-35`) |
| `parallel_exec.rs`, `state_engine.rs` | Parallel exec, state transition + F-01 failure fee (`state_engine.rs:1153`) |
| `post_quantum.rs`, `pq_registry.rs` | Falcon-512 verify (`post_quantum.rs:2319`), PQ key registry + 7200-height rotation delay (`pq_registry.rs:97`) |
| `sharding.rs`, `xshard2pc.rs` | Shards (`MASTERCHAIN_SHARD 0`, `sharding.rs:373`); 2PC gated (`xshard2pc.rs:232-259`) |
| `staking.rs`, `token.rs`, `tokenomics.rs` | Staking math (`staking.rs:59,231,235,294`), token, emission cap (`staking.rs:225`) |
| `turnstile.rs`, `client_ip.rs` | Anti-bot gate, client IP policy |
| `vrf.rs` | ECVRF wiring (classical, default-off; `vrf.rs:56-73,128`) |
| `zkml.rs`, `zkml_attestation.rs` | Re-execution attestations, chain-id singleton (`zkml.rs:220-235`) |
| `liveness_alarm.rs` | Fork/liveness alarms |

## 3. Frozen core (change = spec update + audit + full gate)

1. Wire format: `Block` field layout `sharding.rs:4890-5069` (`shard_headers:4932`,
   `order_merkle_root:4957`, `epoch_key_commitment:4982`, `last_qc:5016`,
   `mmr_epoch_root:5069` last); `QuorumCertificate` shape `consensus.rs:2806-2812`;
   signer-list cap `MAX_COMMIT_CERT_SIGNERS 4096` (`consensus.rs:191`).
2. Quorum: `consensus_quorum_min(n) = floor(2n/3)+1` (`consensus.rs:766-770`);
   live µQC rule `pq_micro_required_power` (`:873-882`); committee cap
   `MICRO_COMMITTEE_MAX_SIZE 64` (`:817`).
3. Apply: `runtime.rs:6884` (`apply_block_fees_rewards`), `:6894`
   (`apply_and_advance`), `:8184` (`apply_block`); failure-fee contract
   `state_engine.rs:1153` (`failure_fee_state`).
4. Admission: chain-id barrier `mempool.rs:1836-1843`, unbound-activation gate
   `:1819-1828` via `chain_binding.rs:38`, pure-PQ refusal `:1844-1859`.
5. Staking math: `MIN_VALIDATOR_BOND` (`staking.rs:59`), slash BPS
   (`:231` equivocation 500, `:235` downtime 10), commission delay 7200 (`:294`),
   emission cap (`:225`), F1 accumulator (`:636-668`).
6. Signature domains: `STELL-MSGSIG-V1` (`wallet_signing.rs:50`),
   `STELL-TYPEDDATA-V1` (`:55`), sortition `STELL_SORTITION_V5` (`consensus.rs:1052`),
   vote/QC magics `VOTE_BLS_MAGIC` (`:204`), `QC_BLS_MAGIC` (`:223`),
   `VOTE_FALCON_MAGIC` (`:329`), `QC_PQ_MAGIC` (`:486`), PQ rotate
   `STELL_PQ_ROTATE_V1` (`pq_registry.rs:119`), session `STELL_SESSKEY_V1`
   (`zkml.rs:209`), VRF family (`vrf.rs:94-128`), CN-VRF family (`cn_vrf.rs:61-65`).

## 4. Crate boundary contracts

- Chain-id singleton: `zkml::effective_chain_id` (`zkml.rs:234-235`,
  env `STELL_CHAIN_ID` `:226`, default 5757 `:220`); consensus freezes it
  (`consensus.rs:48-68`); EVM serves it (`evm_adapter.rs:57-58`).
- PQ verify lives in `stellereum` (`post_quantum.rs:520,2319`); `infnode`
  transport is classical Ed25519/QUIC (`infnode/crates/infnode/src/main.rs:14`)
   with NO pure-PQ mode (per `docs/CLASSICAL_INVENTORY.md:30-34`; confirmed:
   `infnode` QUIC+Ed25519 entry `infnode/crates/infnode/src/main.rs:14`, KEX
   verdict classical-until-ML-KEM-vendored `pq_transport.rs:60-70`, TLS X25519
   flagged classical in inventory).
- `cn_vrf.rs:1-4` is sandbox-only: pure functions + KATs, no consensus call
  site (zero `cn_vrf::` callers outside `cn_vrf.rs` by grep; header
  `cn_vrf.rs:1-4`).

## 5. Light CLI commands (code truth)

- Subcommands (`main.rs:6751-6817`): `LightClient` (`:6751`, opts
  `from`/`verify`/`validators`/`wait_seconds=30`/`verbose` — out-of-band set
  REQUIRED, fail-closed), `LightAnchor` (`:6775`, re-verifies checkpoint
  precommit quorum under set), `LightVerify` (`:6790`, LightHeader-as-successor
  or Checkpoint-as-newer-anchor), `LightRotate` (`:6805`, parses
  `ValidatorSetRotation`, rule enforced by
  `LightClient::rotate_validator_set`).
- Runners (`light_client_cli.rs`): `LightClientOptions` (`:58-68`),
  `run` (`:318`, fetch `height+1` anchoring header, quorum-check, Merkle-proof
  verify), `validator_set_digest` (`:438`, what `light-anchor` prints as set
  hash), `anchor_show` (`:524`), `verify_header_file` (`:556`),
  `rotate_anchor` (`:599`); loaders `load_validator_set` (`:181`),
  `load_checkpoint_file` (`:452`), `load_light_header_file` (`:463`),
  `load_rotation_proof_file` (`:481`). Trust model: root NEVER from server
  (`light_client_cli.rs:11-50`, `LIGHT_CLIENT_VERIFY.md §3`); node-side anchor
  at genesis (`main.rs:2976-2992`), sync-path re-anchor
  (`:1924-1942,:2345-2432`).

## 6. Explorer + WS caps (code truth)

- Explorer: `RateLimiter::new(per_sec)` (`explorer.rs:47`),
  `DEFAULT_RATE_LIMIT_PER_SEC 30` (`:29`, via `default_rate_limit_per_sec`
  `:32`); `MAX_FINALS_LIMIT 100` (`:960`), `DEFAULT_FINALS_LIMIT 20` (`:962`),
  `MAX_ACCOUNT_TXS 20` (`:964`), `MAX_ACCOUNT_DELEGATIONS 50` (`:966`);
  readiness envs `STELL_READY_MAX_STALL_SECS` (`:89`) /
  `STELL_READY_MIN_PEERS` (`:94`).
- WS/subscriptions (`rpc.rs:7216-7357`): `MAX_SUBSCRIPTIONS 4096` (`:7333`,
  per-node memory DoS bound), `MAX_SUBSCRIPTIONS_PER_CLIENT 64` (`:7344`),
  `SUBSCRIPTION_ID_BYTES 16` (`:7347`, 32-hex-char id), `SUBSCRIPTION_TTL_SECS
  3600` (`:7357`); topics `newHeads/newTxs/invalidations/events` (`:16-28`);
  `MAX_RPC_BODY 1 MiB` (`:74`), `MAX_RECENT_BLOCKS 100` (`:1060`),
  `MAX_FINALIZED_HEADERS 512` (`:1108`), `MAX_RECEIPTS 50_000` (`:1111`),
  `MAX_EVENTS_RETURNED 1_000` (`:1237`); per-client caps enforced for
  unattributed creators (`:1156-1177`), estimate-fee limiter
  `ESTIMATE_FEE_RATE_LIMIT_DEFAULT 5` (`:1133-1146`).

## 7. Contracts audit findings + residuals (code truth)

- Crates (`stellereum-contracts/README.md:5`, `Cargo.toml`): live contracts
  `contracts/account-object, liquidity-pool, stl-dns, sts20-token`
  (`stellereum-contracts/contracts/`); SDK/indexer/wallet roles per §1 table.
- Audit state: `stellereum-contracts/README.md:1` + `SECURITY.md:1-9` —
  testnet-only, DRAFT security policy (contact placeholder
  `security@example.invalid`), NO independent external audit completed.
- Findings registry (root audit, not contracts-only):
  `docs/audits/COMPREHENSIVE_AUDIT_REPORT.md:1043-1048` — 35 rows: 26 FIXED,
  5 HOLDS-VERIFIED, 2 ACCEPTED (P4-F-PQ-1 interop wall; P1-G2..G4 filed
  without content, closed R3 per `:1079` + code note
  `consensus_net.rs:3080-3095`), 1 ESCALATED (P2-LEGACY-REPLAY wallet default
  unbound, pins `p2_mempool_pentest.rs:142` / `vp2_verify.rs:725,753`).
- Residuals: external audit NOT conducted (`:117`, owner org);
  legacy cross-chain replay live (`:1154`, A14); snapshot-anchor w/o
  genesis-anchor (`:1190`, C10); live split not conducted + 2PC gate not
  finalized live (`:102`, A2/A3); adopt-path prevote-quorum unwired
  (`:1221`, needs wire change). Red-closure gate green
  (`docs/AUDIT_RED_CLOSURE.md:33-37,154-160`: `audit-repro.sh --no-fuzz`
  PASS 1845/0, `audit_rpc_evm_closeout` 30/30).
