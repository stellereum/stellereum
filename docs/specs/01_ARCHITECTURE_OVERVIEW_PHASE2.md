# 01 — Architecture Overview (HDAE Phase-2, code truth)

Verified on the 2026-11-18 tree (base HEAD `0fdf1eefc` plus the day's in-flight
edits; line numbers match that tree), **after** the module split and
the FULL-PQ wipe. This document replaces the pre-split Phase-2 map: every
top-level single file it used to cite (`consensus.rs`, `runtime.rs`,
`state_engine.rs`, `rpc.rs`, `sharding.rs`, `evm_adapter.rs`, `bls.rs`,
`crypto_privacy.rs`, and the 8000-line `main.rs`) is now a directory or is
deleted. Sections that cannot be re-verified on the current tree are marked
`STALE — see <module dir>` rather than left as false pointers.

> **Ruleset snapshot — historical for consensus values.** Verified under
> ruleset **v2**. Rulesets v3–v5 changed the vote preimage, block identity
> (signed `round`), timestamp bound and chain-wide supply accounting; the
> staking/CN-VRF height windows below were also rescaled by v2. Current values:
> `docs/RULESET_V5.md`, `stellereum/src/protocol.rs`.

Paths relative to repo root unless noted.

## 1. Crates

| Crate / workspace | Role |
|---|---|
| `stellereum` (`stellereum/Cargo.toml:2-3`, package `stellereum 0.1.0`) | Canonical node: consensus, execution, storage, RPC, P2P |
| `infnode` (`infnode/crates/infnode/src/main.rs`) | Overlay: QUIC + PQ transport, DHT, mailbox; `lib.rs` + `dht.rs` + `mailbox.rs` present |
| `infmail` (`infnode/crates/infmail/src/`: `blockchain.rs`, `inbound.rs`, `web.rs`, `main.rs`) | Webmail backend on the overlay |
| `stellereum-contracts/`, `stellereum-indexer/`, `stellereum-sdk/`, `stell-wallet/`, `scripts/tools/stelops/` | Contracts+SDK, SQLite indexer, client SDK, wallet/light client, operator CLI |

Pinned deps (consensus-relevant): `ed25519-dalek v2`
(`stellereum/Cargo.toml:13`), `pqcrypto-falcon 0.4.1` (`:46`, linked by
`src/post_quantum.rs`), `ml-kem 0.3` (`:50`), `argon2 0.5` (`:37`),
`wasmi 2.0.0` (`:38`). There is **no `bls12_381` dependency** any more.

## 2. Module map (`stellereum/src/lib.rs`)

75 entries; the load-bearing ones:

| Module | One-line role |
|---|---|
| `address.rs` | `Stl57` address format |
| `consensus/` (`engine.rs`, `types.rs`, `sortition.rs`, `qc_split.rs`, `rotation.rs`) | BFT core, QC/µQC types, quorum + sortition math |
| `consensus_net.rs` | Broadcast transport, caps, vote coalescing |
| `runtime/` (`mod.rs`, `apply.rs`, `consensus_step.rs`, `anchors.rs`, `lanes.rs`, `cluster.rs`, `mev_sync.rs`) | Block apply, anchor/finality, VDF/apply lanes |
| `state_engine/` (`apply.rs`, `accounts.rs`, `settlement.rs`, `parallel.rs`, `contracts.rs`, ...) | State transition, accounts, CLOB settlement, parallel exec |
| `sharding/` (`block.rs`, `topology.rs`, `transaction.rs`, `xshard.rs`, `envelope.rs`) | Block wire shape, shard topology/boot guard, tx envelopes |
| `rpc/` (`state.rs`, `eth.rs`, `reads.rs`, `writes.rs`, `faucet.rs`, `streams.rs`, ...) | JSON-RPC surface |
| `evm_adapter/` (`adapter.rs`, `types.rs`, `tx.rs`, `crypto.rs`, `rlp.rs`) | EVM compatibility shim (`CHAIN_ID 5757`, `evm_adapter/types.rs:19`) |
| `bridge.rs`, `bridge_adapters.rs` | Bridge limits + adapters |
| `cell.rs`, `chain.rs`, `chain_binding.rs` | State cells, chain store, chain-id/admission binding |
| `cn_vrf.rs` | CN-VRF v1 + v3 primitives; **wired** into `runtime/`, `commitment.rs`, `storage.rs`, `sync.rs` |
| `commitment.rs`, `mmr.rs` | Commitments, MMR epoch roots |
| `contract.rs`, `contract_abi.rs`, `contract_source.rs` | WASM engine, ABI, `.wat` source registry |
| `cpat2.rs` | Compressed patricia trie (exclusion proofs) |
| `wallet_signing.rs`, `wallet.rs` | Message signing, wallet |
| `svm.rs` | SVM execution + gas table |
| `explorer.rs`, `metrics.rs`, `simulator.rs` | Explorer, metrics, deterministic sim |
| `governance.rs` | On-chain gov (`GOVERNANCE_QUORUM_BPS 6666`, `governance.rs:30`) |
| `light_client*.rs` | Light client + CLI |
| `cli/` (`args.rs`, `handlers.rs`, ...) + `node/` (`bootstrap.rs`, `consensus_driver.rs`, `sync.rs`, `policy.rs`, `upgrade_halt.rs`) | Node entry (35-line `main.rs`), CLI, node logic |
| `mempool.rs` | Fee-priority admission |
| `mev*.rs`, `mev_epoch.rs`, `mev_v4.rs` | MEV pipelines |
| `native_api.rs` | 32-method catalog `METHODS` (`native_api.rs:122-379`; first `stell_tokenTransfer` `:125`, last `stell_nativeApi` `:373`) |
| `network.rs`, `sync.rs`, `storage.rs` | Overlay use, catch-up, persistence |
| `node_keys.rs`, `remote_signer.rs` | Key custody, remote signer |
| `oracle.rs`, `orderbook.rs`, `pmm.rs` | Price feeds, CLOB, PMM |
| `parallel_exec.rs` | Parallel execution engine |
| `post_quantum.rs`, `pq_registry.rs` | Falcon-512 verify (`post_quantum.rs:534`, `:2213`), PQ key registry |
| `sharding/topology.rs`, `xshard2pc.rs` | Shards (`MASTERCHAIN_SHARD 0`, `sharding/topology.rs:8`); 2PC active from genesis (`XPC_ACTIVATION_HEIGHT = 0`) |
| `staking.rs`, `token.rs`, `tokenomics.rs` | Staking math (`staking.rs:62`), token, emission cap (`:235`) |
| `turnstile.rs`, `client_ip.rs` | Anti-bot gate, client IP policy |
| `vrf.rs` | Sortition MATH only — no key material, no env, no activation gate |
| `zkml.rs`, `zkml_attestation.rs` | Re-execution attestations, chain-id singleton (`zkml.rs:191,205`) |
| `liveness_alarm.rs` | Fork/liveness alarms |
| `bls.rs`, `crypto_privacy.rs` | **DELETED** (FULL-PQ). Any pointer to them is STALE. |

## 3. Frozen core (change = spec update + audit + full gate)

1. Wire format: `Block` field layout lives in `sharding/block.rs` (STALE — see
   `stellereum/src/sharding/`); `QuorumCertificate` shape
   `consensus/types.rs:1605-1611`; signer-list cap
   `MAX_COMMIT_CERT_SIGNERS 4096` (`consensus/types.rs:198`).
2. Quorum: `consensus_quorum_min(n) = floor(2n/3)+1`
   (`consensus/sortition.rs:24`); live µQC rule `pq_micro_required_power`
   (`:155-164`); committee cap `MICRO_COMMITTEE_MAX_SIZE 128` (`:89`). See
   spec 04 §1 for the exact rule and the code's rationale.
3. Apply: `state_engine/` and `runtime/apply.rs` (STALE — see
   `stellereum/src/state_engine/` and `stellereum/src/runtime/`); failure-fee
   contract `failure_fee_state` (`state_engine/parallel.rs:96`).
4. Admission: chain-id barrier + unbound-activation gate
   (`mempool.rs`, `chain_binding.rs:161`); pure-PQ refusal in the same gates.
5. Staking math: `MIN_VALIDATOR_BOND` (`staking.rs:62`), slash BPS
   (`:265` equivocation 500, `:270` micro-committee 10 000, `:275` downtime 10),
   commission delay 7 200 heights (`:355`), active-validator caps (`:209,:214`),
   emission cap (`:235`), unbonding period (`:260`).
6. Signature domains: `STELL_SORTITION_V5` (`consensus/sortition.rs:425`),
   vote/QC magics `VOTE_FALCON_MAGIC` (`consensus/types.rs:216`),
   `QC_PQ_MAGIC` (`:393`), PQ rotate `STELL_PQ_ROTATE_V1`
   (`pq_registry.rs:126`), session `STELL_SESSKEY_V1` (`zkml.rs:180`),
   CN-VRF family (`cn_vrf.rs`).

## 4. Crate boundary contracts

- Chain-id singleton: `zkml::effective_chain_id` (`zkml.rs:205`, default 5757
  `:191`); the EVM adapter serves the same value (`evm_adapter/types.rs:19,25`).
- PQ verify lives in `stellereum` (`post_quantum.rs:534,2213`); `infnode`
  transport is FULL-PQ (Falcon-512 frame auth, ML-KEM-768 KEX; classical
  offers are refused at every height, `infnode/.../proto.rs:348-378`).
- `cn_vrf` is **not** a sandbox any more: `runtime/`, `commitment.rs:1919+`,
  `storage.rs:4952`, `sync.rs:2781` import it, and the v3 sortition gate exists
  (`consensus/sortition.rs:552-634`, currently `u64::MAX` = dormant).
  The old "zero `cn_vrf::` callers" claim is STALE.

## 5. Light CLI commands (code truth)

- Subcommands (`cli/args.rs:162,186,201,217`): `LightClient`, `LightAnchor`,
  `LightVerify`, `LightRotate`; handlers in `cli/handlers.rs:1692-1735`.
- Runners (`light_client_cli.rs`): `LightClientOptions` (`:58`), `run`
  (`:343`), `validator_set_digest` (`:463`), `anchor_show` (`:552`),
  `verify_header_file` (`:583`), `rotate_anchor` (`:626`); loaders
  `load_validator_set` (`:206`), `load_checkpoint_file` (`:477`),
  `load_light_header_file` (`:492`), `load_rotation_proof_file` (`:510`).
  Trust model: the root is NEVER taken from the server
  (`light_client_cli.rs:11-50`, `LIGHT_CLIENT_VERIFY.md §3`). Node-side
  anchor wiring is STALE — see `stellereum/src/node/` and
  `stellereum/src/runtime/anchors.rs`.

## 6. Explorer + WS caps (code truth)

- Explorer: `DEFAULT_RATE_LIMIT_PER_SEC 30` (`explorer.rs:29`, env override
  `:37`); `MAX_FINALS_LIMIT 100` (`:989`), `DEFAULT_FINALS_LIMIT 20` (`:991`),
  `MAX_ACCOUNT_TXS 20` (`:993`), `MAX_ACCOUNT_DELEGATIONS 50` (`:995`).
- WS/subscriptions (`rpc/streams.rs`): `MAX_SUBSCRIPTIONS 4096` (`:21`,
  per-node memory DoS bound), `MAX_SUBSCRIPTIONS_PER_CLIENT 64` (`:30`),
  `SUBSCRIPTION_TTL_SECS 3600` (`:43`).
- RPC bounds (`rpc/state.rs`): `MAX_RPC_BODY 1 MiB` (`:12`),
  `MAX_RECENT_BLOCKS 100` (`:295`), `MAX_FINALIZED_HEADERS 512` (`:343`),
  `MAX_RECEIPTS 50_000` (`:346`); `MAX_EVENTS_RETURNED 1_000`
  (`rpc/cache.rs:361`). Per-client subscription caps are enforced in
  `rpc/streams.rs:1025-1026` (compile-time ordering asserts).

## 7. Contracts audit findings + residuals

`STALE — see stellereum-contracts/ and docs/audits/`. The old spec cited a
root `COMPREHENSIVE_AUDIT_REPORT.md` with fixed line ranges; the current
authoritative copies are `docs/audits/COMPREHENSIVE_AUDIT_REPORT.md`,
`docs/audits/NEURAL_AUDIT_2026-11-04.md` and
`docs/audits/NEURAL_AUDIT_RETRIAGE.md`. Live contracts and the
"testnet-only, external audit pending" posture are stated in
`stellereum-contracts/README.md:3-7`.
