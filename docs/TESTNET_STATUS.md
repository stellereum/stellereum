# Public testnet status

**Repository-verified: 2026-11-22.** This page describes what the checked-in
code and the recorded v7 rollout support. Testnet state changes; verify the
live values with the commands at the end before relying on them.

Stellereum is a **public testnet**. It has no mainnet, no token sale, and no
guarantee of continuity. Testnet coins have no value, and state, addresses or
parameters can be reset. Do not reuse keys that protect real assets.

## One-line verdict

The public testnet is live on **chain 5757**, **ruleset v7** (`FORK_ID
0x3ae00ebc`), with **4/4 validators** recorded active at the v7 rollout and
**single-block BFT finality**. It runs **shard 0 only**; the fixed `{0,1}`
pair is supported but shard 1 is parked. There is **no external audit**, no
live bridge, no EVM execution, and zkML is re-execution rather than a
zero-knowledge proof.

## What works today

| Capability | Status and evidence |
| --- | --- |
| **Consensus / validators** | The v7 rollout records 4 active validators (`A/B/C/D`), `2000 STELL` self-bond each, `total_power = 8000 STELL`, `quorum = 5334 STELL`, `fragile: false` (`docs/ROADMAP.md`, v7 rollout section). Verify live with `stell_getValidators`. |
| **Chain identity** | Public testnet chain ID `5757` (`0x167d`); the binary default is `DEFAULT_CHAIN_ID = 5757` (`stellereum/src/zkml.rs`). Ruleset `7`, `DOMAIN_SET_VERSION = 4`, `FORK_ID = 0x3ae00ebc` (`stellereum/src/protocol.rs`, `docs/RULESET_V7.md`). |
| **Finality** | Single-block BFT finality: a block is final when it carries a precommit quorum certificate of at least `floor(2·total_power/3) + 1`; one confirmation is final (`stellereum/docs/RPC.md`, “Confirmations”). |
| **Signature / transport** | Falcon-512 in PQ1 envelopes for value and validator votes; ML-KEM-768 for transport. There is no classical or Ed25519 value-signature lane (`docs/specs/02_CRYPTO_AND_PQ.md`, `docs/RULESET_V7.md`). |
| **JSON-RPC** | Native `stell_*` methods plus a read-only EVM-compatible adapter at `https://rpc.stellereum.org` (POST-only). Endpoint and method references: `../docs-site/get-started/networks.md`, `stellereum/docs/RPC.md`. |
| **Explorer and indexer** | Block explorer at `https://explorer.stellereum.org`; indexed history / aggregate queries at `https://explorer.stellereum.org/api/v2`. The indexer is a separate consumer and may lag the RPC tip (`../docs-site/get-started/networks.md`). |
| **Faucet** | Public faucet at `https://faucet-testnet.stellereum.org`, with the published policy: 2 STELL per drip, 45-minute cooldown, 20 requests/hour/IP, 50 STELL lifetime per address (`../docs-site/get-started/networks.md`). The node-side faucet is disabled unless a shared faucet key is configured (`STELL_FAUCET_KEY_FILE`, preferred and `0600`-checked, or `STELL_FAUCET_KEY`). |
| **WASM contracts and native market** | WASM contracts, the on-chain CLOB, PMM, account objects and scoped session keys are part of the protocol (`docs/specs/03_VM_AND_EXECUTION.md`, `../docs-site/core-concepts/native-market.md`). |
| **Operator CLI** | `stellereum` subcommands cover keys, peer stanzas, validator registration, governance, safety migration and upgrade status (`stellereum/src/cli/args.rs`, `stellereum/src/cli/handlers.rs`, `stellereum/docs/OPERATIONS.md`). |
| **Operator tools** | `scripts/join-testnet.sh` and `scripts/run-observer.sh` bootstrap observers; `scripts/cluster_liveness.sh` and `stell-sync.sh health` check liveness; `stelops` reads a stopped store; `stellereum-upgrader` performs a coordinated binary swap; `stellereum-ledger-tool` verifies offline block files. See `../scripts/README.md`, `../stellereum-upgrader/README.md`, `../stellereum-ledger-tool/README.md`. |
| **Upgrade machinery** | Governance commits a `SoftwareUpgrade` plan, the node halts at the plan height, writes `data/upgrade-halt.marker`, exits 42, and refuses to restart consensus until the new binary proves the plan. The upgrader is implemented and drilled but **has not yet been used for a live coordinated upgrade** (`docs/UPGRADE_AND_RECOVERY.md` §7, `docs/UPGRADE_DRILL.md`, `docs/OPEN_DEFECTS.md` UP-5). |
| **Defect register** | `docs/OPEN_DEFECTS.md` has **0 `OPEN` rows**; closed items are `FIXED`/`DEPLOYED`, `BY DESIGN`, or `SEPARATE SYSTEM`. “Fixed locally, not deployed” is tracked separately from “deployed”. |

## What is limited

### Shards: shard 0 only on the public network

* Live public network: **shard 0 (masterchain) only**.
* `{0,1}` is a **supported, fixed public configuration** with two-phase commit
  active from height 0; it is exercised by `scripts/soak_two_shard.sh` and
  documented in `docs/TWO_SHARD_DEPLOY.md`. On the public network, **shard 1 is
  parked**.
* Any other set (`{1}`, `{2}`, `{0,1,2}`, …) refuses startup unless the
  local-soak/test hatch `STELL_EXPERIMENTAL_SHARDS=1` is set. That hatch is not
  part of the public protocol (`stellereum/src/sharding/topology.rs`).

### No bridge is live

No bridge is operated for the public testnet. Do not bridge assets to or from
this network. The repository contains relayer-attested bridge routes, but there
is no production relayer and the external payout leg is not in this tree;
`docs/BRIDGE_THREAT_MODEL.md` describes the trust model and the unimplemented
parts. `SECURITY.md` states the testnet-only, no-real-funds posture.

### EVM is a read-only carrier

There is no EVM interpreter and no EVM state trie. The EVM-compatible JSON-RPC
adapter serves chain identity and read-only views. A value transfer can settle
only as a PQ1 carrier transaction, after a 20-byte EVM address is bound to a
32-byte PQ account. Contract creation and calldata execution are refused with
`evm-contract-execution-unsupported`
(`docs/COMPLETENESS_GAP_ANALYSIS.md` §5, `stellereum/src/evm_adapter/`).

### CN-VRF v3 sortition is not active

Sortition currently uses the parent-hash draw. CN-VRF v3 is imported and
committed in several places, but its sortition gate is deliberately off; it
must not be enabled without a dedicated audit (`docs/PQ_CN_VRF_SPEC.md`,
`docs/ROADMAP.md`).

### zkML is re-execution, not zero knowledge

The zkML opcodes are verifiable re-execution attestations with a Merkle trace.
Every node re-executes and checks the trace. They are **not** zero-knowledge
proofs, succinct proofs, or privacy-preserving inference
(`../docs-site/core-concepts/native-market.md` §“zkML: re-execution, not zero
knowledge”, `docs/ZKML_AUDIT_AND_SEAM.md`).

### No external audit

The code has had internal review, adversarial tests and pentest rounds, but
**no independent external security audit has been completed**. The external
audit brief is a brief, not a report
(`stellereum/docs/audits/EXTERNAL_AUDIT_BRIEF.md`). Treat consensus, bridge,
wallet, RPC and indexer bugs as possible.

### Still deferred

Dynamic shard split/merge, a second independent consensus client, a true ZK
prover/verifier, a full EVM contract interpreter, the wallet UX and
WalletConnect work, and the explorer UI completion are deferred as separate
systems or product work (`docs/ROADMAP.md`, “Deferred Post-Mainnet”;
`docs/OPEN_DEFECTS.md`, “SEPARATE SYSTEM”).

## Known operational constraints

* **Small hosts are part of the measured baseline.** Validators A and D are
  1-vCPU hosts. The measured load-test baseline was sender-bound, not a node
  capacity claim; 107 accepted tx/s is not a 500 tx/s result
  (`docs/LOADTEST_RUNBOOK.md` §0 and §“What these numbers mean”).
* **Disk and inodes are a first-class failure mode.** Run
  `scripts/node-prune-cron.sh` on **every** node, and use
  `scripts/stell-sync.sh preflight` / `health` plus `scripts/doctor.sh` to
  check inode usage, orphan chunks and the store. The watchdog alerts on inode
  pressure and prunes only unreferenced chunks; it never auto-heals config
  drift, a stale consensus lock, lag or divergence (`../scripts/README.md`).
* **DNS seed TXT records are not the working bootstrap path yet.** The code
  supports `STELL_DNS_SEEDS` and `scripts/print-dns-seed-txt.sh` renders the
  records, but public TXT publication is still pending. `scripts/join-testnet.sh`
  and `scripts/run-observer.sh` therefore ship a built-in nodeA/nodeD peer list
  as the working bootstrap path; DNS-only discovery may not find peers until
  the records are published.
* **One process per node for `{0,1}`.** The cross-shard transport is
  node-local; do not run one process per shard. This matters for any future
  shard-1 deployment (`docs/TWO_SHARD_DEPLOY.md`).
* **Upgrades need the whole fleet.** A `SoftwareUpgrade` plan requires the
  governance execution gate to be active. After the halt, restart nodes with
  `STELL_WAIT_SUPERMAJORITY=<halt-height>` (or the CLI flag) so they wait for
  strictly more than 2/3 of the committed power on the same fork and protocol
  version. On timeout the node stays an **observer**, not a voter. Do not
  delete the halt marker to force it back (`docs/UPGRADE_AND_RECOVERY.md` §7).
* **Do not use a live store as backup input.** `stelops` and the ledger tool
  require a stopped store or an independent copy; `backup_verify.sh` proves
  file restorability, not point-in-time consensus consistency
  (`../scripts/README.md`).

## Roadmap summary

Short version, from `docs/ROADMAP.md`:

1. Finish the operational follow-ups from the v7 rollout: a longer soak and the
   first real supervised upgrade.
2. Decide the shard-1 posture (keep it parked or fund and serve it); dynamic
   split/merge remains out of scope.
3. Finish legacy replay-protection rollout and the remaining product surfaces
   (wallet UX, WalletConnect, explorer UI).
4. Keep the CN-VRF v3 sortition gate off until its audit; the parent-hash draw
   remains the live mechanism.
5. Keep the release gate green: `scripts/verify_testnet_ideal.sh` (clippy,
   fmt, tests, 4-node sim harness).
6. External audit, mainnet and any real-value deployment remain organisational
   and out-of-scope work, not testnet features.

## Verify it yourself

Read-only checks; no transaction, restart or key operation:

```sh
RPC=https://rpc.stellereum.org

curl -sS "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_chainId","params":[]}'
# expect 5757

curl -sS "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_blockNumber","params":[]}'

curl -sS "$RPC" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"stell_getValidators","params":[]}'
# check set size, power, quorum, fragile
```

Check height advancement without restarting anything (supply more than one
`--rpcs` endpoint to check divergence):

```sh
scripts/cluster_liveness.sh \
  --rpcs "A=https://rpc.stellereum.org" \
  --expected-block-time 1 --window 30
```

Run the repository gate (local build/test only; no live cluster access):

```sh
./scripts/verify_testnet_ideal.sh --fast
```

## Source of truth

This page replaces the former internal protocol-freeze working note. Source
comments that still cite that note are referring to the same decisions now
recorded in `docs/RULESET_V7.md` and on this page.

* `docs/OPEN_DEFECTS.md` — defect register, currently 0 `OPEN`.
* `docs/ROADMAP.md` — what is done and what is next.
* `docs/RULESET_V7.md` — the current consensus ruleset and activated gates.
* `stellereum/docs/audits/KNOWN_ISSUES.md` — known weaknesses and documented
  non-goals.
* `SECURITY.md` — disclosure policy and testnet-only posture.
