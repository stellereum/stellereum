# PLAN-BINDING — full chain-binding rollout (A14 structural fix)

Status: **PHASE 1 SHIPPED + SCAFFOLD EXTENDED** (warn+meter live; activation
plumbing, refusal string and drain helper built as spec-as-code, not yet
wired). Phases 2–3 specified for a follow-up.

## 1. Problem (verified)

Transaction wallets default to UNBOUND envelopes: `Transaction::sign`
(`src/sharding.rs:2457`) and the default wallet constructors build no chain
id (`PqSignatureEnvelope.chain_id: None`, `src/sharding.rs:39`;
opt-in `*_with_chain` constructors carry it). An unbound signature verifies
on ANY deployment with the same key: testnet txs replay on mainnet. Votes
and blocks are already bound (`vote_sign_bytes` commits
`consensus_chain_id`, `src/consensus.rs:1202`; `Block::compute_hash` commits
it, `src/sharding.rs:5341`; EVM settlement enforces `chain_id == 5757`,
`src/sharding.rs:2930`) — transactions are the open surface, which is why
this rollout is shaped as admission refusal, not a signature-format change.

Shipped phase 1 (do not regress): `note_unbound_admission`
(`src/rpc.rs:2812`) warns + `stell_unbound_tx_total` meters
(`src/metrics.rs:143`, `inc_unbound_tx`); bound envelopes (CH1
`is_chain_id_bound`, session `delegation`, PQ `chain_id`, EVM) stay silent.
Wallet defaults still unbound behind the loud `unbound_legacy_*` hatch
(`src/wallet.rs:648,663`); bound constructors `create_bound_transaction` /
`create_bound_payload_transaction` (`src/wallet.rs:595,618`) are opt-in.

## 2. Consensus-breaking surface (exact — by grep, not guessed)

Refusal changes WHICH transactions are valid, so it breaks consensus at
activation on purpose. Every admission/verification site below must flip on
the SAME height or mixed-version nodes finalize different blocks:

| # | Struct / hash / preimage | File:line | What changes and why |
|---|---|---|---|
| 1 | RPC admission: `stell_sendRawTransaction` + `admit_signed_payload_tx` (+ second `note_unbound_admission` site `src/rpc.rs:5120`) | `src/rpc.rs:2812,2874,5121` | Phase 3 returns `UNBOUND_REFUSED_ERR_PREFIX…` (see §5) instead of admitting. Same predicate, same height on every node — else mempools diverge and proposers build different blocks. |
| 2 | Mempool checked admission (`insert` / `add_checked_ctx`, nonce-gap + balance gates nearby) | `src/mempool.rs:1686,1906` | Phase 3 refuses unbound at insert (defense in depth: a transaction that bypasses the RPC — gossip, restore — still cannot queue). `MempoolError` gains a variant; backup/restore re-admission (`~1306`) must drop unbound at `h >= H_bind`. |
| 3 | Block-apply gates (`state_engine.rs:2936`, packing filter `~4440`, session gate `~7210`) | `src/state_engine.rs:2936,4440` | Today `if let Some(cid)` MISmatch refuses, `None` passes. Phase 3: `None` refuses at `h >= H_bind`. The packing filter and the session-policy gate flip identically — else execution and proposal disagree and the state root forks. |
| 4 | `Transaction::verify_signature_for_chain` / `chain_id()` | `src/sharding.rs:2962,3494` | Pure helpers unchanged; phase 3 passes `require_chain_id=true` at every call site at/after activation (grep all callers then — today only wallet tests + a few gates use it). |
| 5 | Wallet defaults (`create_*` vs `unbound_legacy_*`, session/PQ/EVM constructors) | `src/wallet.rs:582,595,618,648,663`, `src/sharding.rs:2573,3096,3143,3179` | Phase 2 flips defaults to bound (unbound hatch stays, loud). No consensus bytes change for already-bound flows; unbound flow shrinks to explicit opt-in so phase-3 refusal strands nobody by surprise. |
| 6 | `Transaction::compute_tx_hash` / `signing_message` chain commitments | `src/sharding.rs:3020,3436` | UNCHANGED (conditional commitments already cover bound txs; unbound txs keep their hashes — refusal is about validity, not re-hashing). Block hashes therefore do NOT move at activation for bound-only chains. |

Tests / golden vectors that change at phase 3 (re-pin then, not now):

* `src/rpc.rs:8765` `unbound_admission_is_metered_and_bound_is_silent` — becomes refuse-after-height (height-parameterized).
* `src/wallet.rs:1117,1146` (bound constructors, legacy hatch) — defaults flip in phase 2.
* `tests/*chain*` + `tests/blockchain_security_tests.rs`, `chain_mempool_security_tests.rs` — any fixture submitting unbound txs must bind or expect refusal.
* `src/metrics.rs` unbound-counter tests — counter keeps its name (history continuity); phase 3 adds drop-at-activation series (see §6).
* NOT broken: vote/block/EVM vectors (already bound), `compute_tx_hash` of bound txs, bound wallet vectors (`src/wallet_signing.rs`).

## 3. Migration plan (keeps the live chain running)

* **Phase 1 — ACCEPT-NEW + EMIT-OLD (SHIPPED, plus scaffold this change).**
  Shipped: admit + warn + meter (`rpc.rs`, `metrics.rs`). Scaffold built
  this change (`src/chain_binding.rs`, NOT wired): `ChainBindingActivation`
  (`STELL_CHAIN_BIND_ACTIVATION_HEIGHT`, default `never()` = `u64::MAX`),
  pure `check_admission(is_bound, height, activation, chain_id)`,
  `unbound_refused_err(height, chain_id)` + pinned
  `UNBOUND_REFUSED_ERR_PREFIX`, `wallet_requirement_doc`,
  `partition_at_activation` (pure mempool-drain helper), atomic
  `unbound_dropped_at_activation`. Emission: unchanged (wallets still
  default unbound). Refusal: none (every admission path byte-identical).
  Rollback: delete the module — nothing calls it.
* **Phase 2 — emit-new (follow-up, no refusal).** Flip wallet defaults to
  bound (`create_bound_*` become THE constructors; `unbound_legacy_*` stays
  explicit + loud), ship bound-by-default CLI/RPC examples, publish the
  requirement via `wallet_requirement_doc` in RPC help + `docs/` +
  `VALIDATOR_ONBOARDING.md`. Activation height `H_bind` announced (scheduled
  height, governance-agreed, §4). Unbound flow still admitted + metered —
  the meter time-series going flat is the readiness signal. Mixed-version:
  full interop (no validity change anywhere).
* **Phase 3 — refuse-old (follow-up, flag-day at `H_bind`).** Wire
  `check_admission` into §2 sites 1–3 with `require_chain_id=true`;
  `partition_at_activation` runs once when crossing `H_bind` (in-flight
  unbound mempool txs DROP — see §5 for why no grandfathering); block-apply
  refuses unbound at `h >= H_bind`. In-flight unbound transactions already
  IN blocks pre-`H_bind` stay valid (history never re-verified under new
  rules — replay of pre-`H_bind` history uses height-gated verify, the same
  pattern as every trailing-field activation in `sharding.rs`).

## 4. Activation mechanism

Scheduled height `H_bind` (governance-agreed, published; read from
`STELL_CHAIN_BIND_ACTIVATION_HEIGHT`, default never). Why a flag-day height
and not a governance vote: a vote cannot securely activate replay protection
(pre-activation votes are themselves replayable — the vote would need the
rule it enacts). Mixed-version behaviour per phase:
* Phases 1–2: no validity change — old and new nodes agree on everything;
  the only divergence is wallet DEFAULTS (phase 2), which is user-visible,
  not consensus-visible.
* Phase 3 at `H_bind`: nodes that flipped refuse unbound; nodes that did
  not still accept it. THIS IS A CONSENSUS DIVERGENCE BY DESIGN if versions
  mix — hence: (a) long phase-2 soak with the flat-meter readiness gate,
  (b) coordinated all-validators upgrade before `H_bind` (same rollout rule
  as `STELL_PROPOSER_V1` / MMR commitments), (c) pre-`H_bind` blocks verify
  under old rules forever (height-gated, no history rewrite).

## 5. Admission refusal + in-flight policy (specified)

* Which height/flag activates: `chain_height >= H_bind` with
  `H_bind = ChainBindingActivation::from_env().height` (default
  `u64::MAX` = never). `is_bound = tx.chain_id().is_some()` — covers CH1,
  session grants (`delegation.chain_id`), PQ `envelope.chain_id`, EVM
  (`EVM_CHAIN_ID`); stealth/legacy signatures without any envelope are the
  refused class.
* In-flight unbound mempool txs at activation: DROPPED
  (`partition_at_activation`), counted (`unbound_dropped_at_activation`)
  and logged — NOT grandfathered. Grandfathering would let a pre-activation
  unbound tx be included post-activation, forking upgraded vs non-upgraded
  verifiers on the same block. Proposers additionally filter at packing
  (belt and suspenders: the apply gate is authoritative).
* Wallet discovery: the RPC refusal string IS the discovery mechanism —
  `rejected: unbound transaction refused: chain binding enforced at height
  {H}; re-sign the transaction bound to chain_id {id} (wallet:
  create_bound_transaction / new_*_with_chain; see docs/PLAN-BINDING.md)`
  (built: `unbound_refused_err`), stable prefix
  `UNBOUND_REFUSED_ERR_PREFIX` for programmatic match, plus
  `wallet_requirement_doc` in RPC help/CLI/docs. No new RPC method is
  needed; a new method would itself need versioning.

## 6. Rollback

* Abort phase 2: flip wallet defaults back — no consensus state involved.
* Abort phase 3 BEFORE `H_bind`: ship a binary with the height moved out
  (or env unset) — unbound flow resumes admitting. AFTER `H_bind` finalized
  unbound-free blocks: rollback = pre-`H_bind` snapshot + old binary, with
  the standard flag-day cost. The `stell_unbound_tx_total` series stays
  exported forever (audit trail that the rollout completed); the new
  drop-at-activation counter distinguishes "refused at RPC" from "dropped
  from queue".

## 7. What was built vs specced

* BUILT: phase 1 warn+meter was already shipped (`src/rpc.rs:2812`,
  `src/metrics.rs:143`); this change adds the unwired scaffold
  `src/chain_binding.rs` (activation, predicate, refusal string, drain
  helper, doc string) with unit tests (`cargo test --lib chain_binding::`).
  No admission path touched.
* SPECCED (follow-up): phase-2 wallet default flip + `H_bind` announcement;
  phase-3 wiring into `rpc.rs` / `mempool.rs` / `state_engine.rs` +
  one-time `partition_at_activation` at `H_bind` + height-gated historical
  verify.
