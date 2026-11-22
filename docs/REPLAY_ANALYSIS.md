# Replay-Protection Gap Analysis

Date: 2026-10-30. Scope: read-only review + tests. No src changes, no live ops.
Gate under review: height-gated envelope refusal, default-OFF
(`STELL_CHAIN_BIND_ACTIVATION_HEIGHT` unset → `ChainBindingActivation::never()`).

## Full replay-defense chain (as built)

| Layer | Mechanism | Code ref |
|---|---|---|
| Envelope height-gate | `verify_transaction_envelope_at_height[_with_activation]` → `check_admission`: unbound refused at/after H_bind; bound always strict-matched to `consensus_chain_id()` | `stellereum/src/consensus.rs:106-147`, `stellereum/src/chain_binding.rs:127-137` |
| Activation source | `STELL_CHAIN_BIND_ACTIVATION_HEIGHT`; unset/unparsable/`0` → `never()` (refuses at NO height, incl. `u64::MAX`) | `chain_binding.rs:33-77`, `consensus.rs:110` |
| Chain-id in signed bytes | CH1 envelope: sig = `64B sig ++ "CH1" ++ chain_id BE`; `signing_message()` appends `CHAIN_ID_COMMITMENT_TAG ++ chain_id`, so the id cannot be swapped post-signing. Same commitment covers session-delegation, PQ-envelope, and sponsor-grant ids via `chain_id()` | `stellereum/src/sharding.rs:591-592,627,2655-2666,2855-2859,3525-3560`; `chain_id()` at `3006-3030` |
| Strict cross-chain check | `verify_signature_for_chain(expected, strict)`: any bound id ≠ local → `false` at EVERY height; `strict` (= gate-active) additionally refuses id-less envelopes | `sharding.rs:3583-3599`, `consensus.rs:136-147` |
| Nonce execution gate | `apply_transaction`: `tx.nonce != sender.nonce` → refuse (stale nonce moves nothing; attributable-failure rules charge floor + consume nonce so failures are not free-replayable) | `state_engine.rs:3060-3066`; failure-fee contract `tests/failure_fee_contract_tests.rs:128-179` |
| Mempool nonce-gap fail-fast (F-02) | `insert` enforces `check_nonce_gap` (head = mex of on-chain nonce + pooled nonces; window `NONCE_FUTURE_WINDOW = 4`) when caller carries `AdmissionCtx::with_onchain_nonce`; past-window → `Err(NonceGap)`, nothing pooled touched | `mempool.rs:1775-1790,2089-2130`; `NONCE_FUTURE_WINDOW` at `685`; test `vuln_bundle_tests::insert_enforces_nonce_gap_from_context` |
| Mempool TTL sweeps | `evict_unexecutable[_at]` reclaims stale-nonce/unaffordable + aged future nonces (`FUTURE_NONCE_TTL_SECS = 60`); `sweep_expired` reclaims gap-stuck/unexecutable older than `STUCK_TX_TTL_SECS = 120` | `mempool.rs:1584-1675,2132-2222`; consts at `686-703` |
| Shard binding | `source_shard`/`target_shard` are in the signed base message; pool-level + ctx-level shard pin refuses foreign-shard admission | `sharding.rs:2760-2778` (`base_signing_message`), `mempool.rs:1726-1753` |
| Cross-shard dedup | consumed/produced/completed replay sets committed into state root (`XSHARD_REPLAY_V1`); duplicate delivery refused; snapshot install fail-closed on missing blob | `commitment.rs:1502-1533`, `tests/xshard_replay_tests.rs` |
| Phase-1 metering (WIRED) | RPC `stell_sendRawTransaction` + `admit_signed_payload_tx` admit unbound with warn + `stell_unbound_tx_total` counter | `rpc.rs:3014-3030,3079-3080,5519-5520` |
| Wallet pre-check | `check_envelope_binding_at_height` (pure, submit-time) | `wallet.rs:667-693` |

NOT wired (verify-only scaffolding, by module's own admission at
`chain_binding.rs:14-19`): `check_admission` is called from NO production
admission path — `rg` shows callers only in `consensus.rs` (the gate fn
itself), `wallet.rs` (pre-check), and tests. `rpc.rs`, `mempool.rs::insert`,
and `state_engine.rs` block/apply gates never call it; `partition_at_activation`
has no call site; `main.rs` contains no `STELL_CHAIN_BIND_*` wiring (only the
unrelated `xpc_activation_from_env` pattern at `main.rs:2599`).

## Verification runs (this session)

- `cargo test -p stellereum --test wallet_chain_binding_tests` → 5 passed, 0 failed
  (bound pre/post-activation; unbound pre-compat; unbound post-refusal w/ pinned
  prefix; cross-chain refuse at every height; default-off admits).
- Replay/nonce/mempool batch → all green:
  `historical_attacks_tests` 8, `failure_fee_contract_tests` 4,
  `fee_market_live_tests` 8, `chain_mempool_security_tests` 20,
  `mempool_econ_tests` 3, `vuln_bundle_tests` 8, `xshard_replay_tests` 5.
- Second batch → `p2_mempool_pentest` 1, `mempool_mev_audit_closure_tests` 10,
  `fee_market_tests` 17, `pq_fork288000_replay` 5. All ok.
- `cargo test -p stellereum --lib chain_binding` → 6 passed.
- `cargo clippy -p stellereum --all-targets -- -D warnings` → 0 warnings, 0 errors.
- No failures to diagnose; no test-only fixes needed.

## Per-scenario verdicts

(a) Same tx resubmitted, same height — COVERED (independent of gate).
`state_engine.rs:3061` nonce-equality + mempool `Duplicate` hash check
(`mempool.rs:1972-1974`) refuse it. Proven by
`failure_fee_contract_tests::a_replay_or_a_nonce_gap_moves_nothing` and
`fee_market_live_tests` (spent-nonce flood occupies no block space).

(b) Tx replayed at a later height — COVERED iff gate armed (WIRED 2026-10-30,
see note at end); EXPOSED by default.
With activation set: unbound envelope refused at `height >= H_bind` on every
production admission path — RPC submit (`rpc.rs`: `stell_sendRawTransaction`,
`admit_signed_payload_tx`, `eth_sendRawTransaction`; height = finalized-tip+1
from committed state, refusal is the check's message verbatim), mempool insert
(`mempool.rs::insert` via `AdmissionCtx::chain_height`, `UnboundRefused` +
`stell_unbound_refused_total`), and block apply (`state_engine.rs` admission
pass at the COMMITTED block height plus single-tx apply; admission-stage
refusal — no fee, no nonce, exactly like the chain-id mismatch) — plus a
one-shot pool drain at the crossing height (`main.rs`). Proven by
`tests/replay_enforcement_tests.rs` (8/8: per-step refused-armed vs
admitted-unset differentials on the SAME fixture, plus same-height resubmit
controls). Default-off (`never()`): unchanged — unbound admits under legacy
rules forever; a captured pre-activation unbound tx still replays at ANY later
height until the sender's nonce advances. The gate must still be ARMED
(scheduled `H_bind` per `docs/PLAN-BINDING.md`) to close this.

(c) Cross-shard replay — COVERED (independent of gate).
Shard ids are signed (`base_signing_message`, `sharding.rs:2760-2778`);
mutating either breaks `verify_signature`. Proven by
`historical_attacks_tests::etc_cross_shard_replay_rejected` plus
`xshard_replay_tests` (5/5) for message-level dedup.

(d) Cross-chain replay, same keys, different chain-id/epoch — COVERED for bound
envelopes at every height, pre- and post-activation (strict chain match does
not depend on `refusal_active`; proven by
`cross_chain_replay_refuses_at_every_height`). EXPOSED for unbound envelopes
while default-off: no chain id in signed bytes → a testnet-captured unbound tx
verifies on mainnet (WIRED 2026-10-30, see note at end: with the gate armed
the same RPC/mempool/apply refusals as (b) stop unbound cross-chain replays
too — an unbound envelope carries no chain id to match, so the height gate is
its only refusal). Session/PQ/sponsor/EVM envelopes all report through
`chain_id()` (`sharding.rs:3013-3030`) and are covered when present. Note:
EVM settlement pins `chain_id == 5757` (`evm_adapter.rs:522-539,633`) while
`consensus_chain_id()` follows `STELL_CHAIN_ID` — on a non-5757 deployment EVM
txs fail closed (refused, not replayable). Epoch is NOT part of the replay
domain (no epoch in signed bytes); replays across epochs on the SAME chain
rely solely on the nonce gate.

(e) Nonce-gap stuffing lockup — COVERED (independent of gate).
Admission fail-fast (`NONCE_FUTURE_WINDOW = 4`, `mempool.rs:1775-1790`),
`FUTURE_NONCE_TTL_SECS = 60` reclamation of aged future nonces
(`evict_unexecutable_at`), 120 s stuck-Tx sweep (`sweep_expired`), per-sender
quota + joint-balance reservation (F-03). Proven by
`vuln_bundle_tests::insert_enforces_nonce_gap_from_context` and
`chain_mempool_security_tests` (20/20). Residual: `check_nonce_gap` only
enforces when the caller supplies `AdmissionCtx::with_onchain_nonce`
(`mempool.rs:1786`); paths passing `None` keep legacy call-site pre-checks —
one forgotten `None` re-opens stuffing on that path (defense in depth gap,
not a live hole while all current call sites carry the head).

(f) Envelope with forged height — COVERED as designed, with a wiring caveat.
The envelope carries no height; the gate compares caller-supplied
`chain_height` against activation. Forgery therefore means a CALLER lying
about height, not a tx-field edit — and today there are no production callers,
so nothing can lie yet. When phase 3 wires it, the height MUST be the
committed block height at propose/apply (not an RPC-supplied or mempool-local
value), or a mixed-version fork re-opens: post-activation nodes refusing what
pre-activation nodes include is exactly the fork `partition_at_activation`
exists to prevent (`chain_binding.rs:140-144`).

## What default-off leaves exposed (summary)

1. Unbound envelopes replay across heights (b) and across chains (d-unbound)
   indefinitely — the gate refuses nothing until `STELL_CHAIN_BIND_ACTIVATION_HEIGHT`
   is set. Phase-1 metering (`stell_unbound_tx_total`) observes but does not stop.
2. The refusal itself is unwired: even WITH the env set, RPC/mempool/apply admit
   and include unbound txs (no `check_admission` call, no `partition_at_activation`
   drain, no apply-path chain check beyond `tx.chain_id` match in
   `state_engine.rs:2999-3006`, which passes unbound through). Setting the env
   today changes verdicts only inside `verify_transaction_envelope_at_height`,
   which no block path calls.
3. Epoch is not a replay domain; same-chain cross-epoch replay rests on nonces alone.

## Recommendation

1. Do NOT just set the env: without phase-3 wiring it is a no-op on live paths
   (finding 2). Wire in this order: RPC refusal (`stell_sendRawTransaction`,
   `admit_signed_payload_tx`, `eth_sendRawTransaction` mapped path) →
   `mempool.rs::insert`/`add_checked_ctx` → block propose/apply gates in
   `state_engine.rs` (using committed block height) + one `partition_at_activation`
   drain at the crossing height. Each step gets a differential test (admit-before /
   refuse-after on the same fixture) before the next.
2. Then schedule and publish `H_bind` per `docs/PLAN-BINDING.md` (flag-day height,
   not a vote), with wallet discovery strings (`wallet_requirement_doc`) shipped
   first so post-activation refusals are actionable.
3. Close the two minors during wiring: require `with_onchain_nonce` on every
   `insert` call site (e), and record the height-source rule (committed block
   height only) as an inline `// GATE:` comment at each new call site (f).
4. Optional hardening (not blocking): bind epoch (or `sealed_epoch`-style domain)
   into `signing_message` so same-chain cross-epoch replay does not rest on
   nonces alone; reconcile the EVM 5757 pin with `STELL_CHAIN_ID` deployments.

## 2026-10-30 wiring update (phase 3, this session)

`check_admission` is now called on every production admission path behind the
SAME `STELL_CHAIN_BIND_ACTIVATION_HEIGHT` env (no new env names), via the new
`chain_binding::check_admission_from_env` helper. Default-off stays
byte-identical on all three steps, pinned by
`tests/replay_enforcement_tests.rs::default_off_full_path_accepts_with_env_unset`
(full RPC → mempool → apply run with the env unset, expecting acceptance).
This resolves finding 2 above (setting the env is no longer a no-op on live
paths) for scenario (b) and the unbound half of (d). Gate pasted in the
task report: clippy 0/0, new tests 8/8, `wallet_chain_binding_tests` 5/5,
`chain_mempool_security_tests` 8/8, `mempool_mev_audit_closure_tests` 10/10.
Residuals (unchanged from the analysis, still open): epoch is not a replay
domain; faucet-built and restore-re-admitted transactions carry no height
(legacy admit; the one-shot drain + apply gate still catch them
post-activation); no propose-time filter (post-activation unbound inclusions
fail uniformly at apply instead); changing the env mid-run needs a restart
to take effect uniformly.
