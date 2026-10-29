# Stellereum — Developer Documentation

**Language: English.** The repo's operational notes are Russian-heavy
(`stellereum/docs/OPERATIONS.md` §15, handoff memos), but every code
identifier, RPC method, error string and protocol invariant is English.
Auditors, wallet integrators and future node operators need one language
that matches the code; that language is English. Russian sources are linked
where they are the authority.

## What Stellereum is

Stellereum (STELL) is a post-quantum, sharded, non-EVM Layer-1 blockchain
written in Rust: Ed25519 + Falcon-512 hybrid signatures, BFT consensus with
a stake-weighted sortition fast path (µQC), TON-style workchain sharding
with a two-phase cross-shard commit, a WASM contract engine, and a native
orderbook. **Stage: public testnet. The code has passed internal review
waves but no independent external audit has been completed — do not use
real funds or mainnet keys** (see [06-security](06-security.md)).

Canonical in-tree sources this site is built from:

| Source | What it owns |
| --- | --- |
| `stellereum/PROTOCOL.md` | consensus state, transitions, invariants |
| `stellereum/docs/RPC.md` | every `stell_*` method that exists |
| `stellereum/docs/SHARDING.md` | routing rule, split/merge, 2PC |
| `stellereum/docs/OPERATIONS.md` | running a node, incidents §§7,14,15 |
| `stellereum/docs/VALIDATOR_ONBOARDING.md` | bond → propose → claim → leave |
| `stellereum/docs/audits/KNOWN_ISSUES.md` | 36 known issues (KI-01…KI-36) |
| `stellereum/docs/audits/THREAT_MODEL.md` | STRIDE model, attacker classes |
| `/SECURITY.md` (repo root) | reporting policy (placeholders) |

Rule used on every page: no invented endpoints, commands or numbers —
each claim names the file/symbol it was grepped from. Anything not yet
verified against a live node is marked `TODO` with the exact command.

## Architecture map

```text
                    ┌─────────────────────────────┐
                    │   MASTERCHAIN (shard 0)     │  global config, validator
                    │   consensus + staking +     │  set, shard-head commits
                    │   governance + 2PC hub      │  (PROTOCOL.md §5.1)
                    └────────────┬────────────────┘
                                 │ longest-prefix routing
                    ┌────────────▼────────────┐  ┌────────────────────────┐
                    │ WORKCHAIN shard(s)      │  │ WASM contracts (SVM)   │
                    │ accounts, CLOB, STS     │  │ 13 host fns, fuel      │
                    │ tokens, PMM, sessions   │  │ (03-contracts)         │
                    └─────────────────────────┘  └────────────────────────┘
```

- Consensus: propose → prevote → precommit → commit, quorum
  `floor(2·power/3)+1`, chain-id-bound votes/blocks ([02-concepts](02-concepts.md)).
- Finality is single-block BFT: **1 confirmation is final**
  ([02-concepts](02-concepts.md)).
- Money movement on failure follows the F-01 failure-fee rule
  ([02-concepts](02-concepts.md)).

## Where to start

| Persona | Path |
| --- | --- |
| **Developer** | [01-quickstart](01-quickstart.md) (60-min loop) → [02-concepts](02-concepts.md) → [03-contracts](03-contracts.md) |
| **Validator** | [04-validators](04-validators.md) → `VALIDATOR_ONBOARDING.md` in-tree → [05-operators](05-operators.md) §10–§11 |
| **Auditor** | [06-security](06-security.md) → `audits/KNOWN_ISSUES.md` → `audits/THREAT_MODEL.md` → `PROTOCOL.md` invariants |
| **Wallet integrator** | [02-concepts](02-concepts.md) (addresses, fees, confirmations) → `docs/RPC.md` §§2–4 → `docs/WALLET_SIGNING.md` → `../../stellereum-sdk/SDK-README.md` (canonical tx builders — use the SDK, don't hand-roll bincode) |

Pages: 00 index · 01 quickstart · 02 concepts · 03 contracts ·
04 validators · 05 operators · 06 security · 07 glossary.
