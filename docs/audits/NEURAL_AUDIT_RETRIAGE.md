# Neural audit re-triage vs CURRENT HEAD (`4e3fcdd35`)

- Audit source: `docs/audits/NEURAL_AUDIT_2026-11-04.md` + `NEURAL_AUDIT_2026-11-04_FINDINGS.csv`
  (audit commit `e58323db…` — **not present in this history**: `git rev-parse e58323db` fails;
  this lineage's root is HDAE baseline `833c71ea0`. Triage below is by CURRENT HEAD code shape,
  every row backed by a read/command in this session. Line numbers are HEAD's; audit lines shifted.)
- HEAD: `4e3fcdd35` (all paths below are under `stellereum/`).

## Verdict table

| ID | Verdict | Evidence (read / command output) | Action |
|----|---------|----------------------------------|--------|
| C-01 | STILL-OPEN | `stellereum/src/rpc.rs:5728-5737` (`g.propose` on shared gov+ledger), `:5774-5782` (`g.vote`), `:5817-5821` (`g.execute`) — still direct shared-object mutation, no block-carried path. `rg gov_action_from_params` shows no block-op wiring. | fix-wave |
| C-02 | STILL-OPEN | `rpc.rs:5730-5733` proposer from unsigned param (default `[1u8;32]`); `:5756-5759` voter unsigned; `runtime.rs:2597` `gov_finalize` defined but `rg gov_finalize` across `src/`+`tests/` shows **zero callers**. Partial mitigation only: token gates when configured. | fix-wave |
| H-01 | PARTIALLY-FIXED | Gates **added** where missing: `rpc.rs:5784-5808` executeProposal (W6.7 comment), `:6467-6483` deploy, `:6737-6752` call (P5 comments). BUT fail-open-on-`None` retained by design: `if let Some(expected)` at `rpc.rs:5687,5740,5797,6472,6741`; `write_methods_require_auth_token` test asserts open submission by design (`rpc.rs:11133-11142`); P5 test comment "fail-open when unconfigured, like the rest" (`rpc.rs:11160-11161`). Only mempoolDump (`:5862-5871`) + SIGN arms fail closed on `None`. | fix-wave |
| H-02 | ALREADY-FIXED | `rpc.rs:380-393` `dev_msg_signing_seed_from_env()` (ephemeral, `None` unless `STELL_DEV_UNSAFE_TESTKEY=1`); both live sites use it (`main.rs:554`, `:8089`); fail-closed gates `require_wallet_sign_auth` (`rpc.rs:3907-3923`), loopback-only (`:3925-3939`), refuse-without-seed (`:4036-4043`); `handle_sign_message` signs from seed only (`:4023-4045`). Protection present since lineage baseline `833c71ea0` (`git log -G msg_signing_seed` → only baseline; no post-audit delta exists in this history). Green: `sign_refuses_*` 3 passed, `sign_needs_token_but_verify_is_public` 1 passed (`cargo test --lib`, this session). | none |
| H-03 | STILL-OPEN | Direct-mutation shape intact: `debit_native`/`credit_native` `rpc.rs:6878-6887` + inline `call_contract_*_structured` `:6889-6905`, then mempool `add` `:6942` + pre-mined receipt `:6962-6975` (double-apply on inclusion). P5 comments cover only auth gate (`:6738-6740`) + `from==signer` (`:6837-6847`) — not the double-exec. No clone-only/read-only rework, no removal. | fix-wave |
| H-04 | STILL-OPEN | `private_key` still accepted `rpc.rs:6611-6624`, `:6814-6827`; direct `deploy_contract_deterministic[_with_abi]` into engine `:6539-6546`, `:6660-6685` before/outside block + mempool add after. Partial: `from==signer` (`:6634-6644`), wrapped-tx `verify_signature` (`:6501-6506`). Root (key-over-RPC + out-of-block deploy) remains. | fix-wave |
| M-01 | STILL-OPEN | Still opt-in: `post_quantum.rs:71-89` (`is_pure_pq_enforced` false unless `STELL_PURE_PQ=1/true/always` or `--pure-pq`); `main.rs:2838-2847` default logs "Dual-Stack". No `STELL_PURE_PQ` in repo configs (no `testnet/`/`docker/` dirs in this tree). | fix-wave |
| M-02 | PARTIALLY-FIXED | Serve side unified: `effective_chain_id()` (`evm_adapter.rs:57-58`) used by `eth_chainId`/`net_version` (`:216-234`) with deliberate-pin docs (`:37-49`). Verify side still hard-pins `CHAIN_ID` 5757 (`:471`, `:543`, `:582`, `:633`). Mismatch persists iff `STELL_CHAIN_ID≠5757`. | fix-wave |
| M-03 | STILL-OPEN | `restore_pq_keys` (`state_engine.rs:8139-8175`) installs pairs verbatim; salt destructured as `_salt` and discarded; no `blake3(pk)`/`derive()` vs address check. `DEFAULT_SALT` still hardcoded at healing sites (`:3263`, `:4874`, `:10496`, …). | fix-wave |
| M-04 | STILL-OPEN | `cell.rs:165` `with_capacity(roots_len)`, `:176` `with_capacity(cells_len)` from unvalidated u32 prefix; only per-item EOF checks follow. No `try_reserve`/remaining-bytes pre-check. | fix-wave |
| M-05 | PARTIALLY-FIXED | Per-crate locks exist (`stellereum/Cargo.lock`, +6 others per `git ls-files`); `infnode` is now a local path dep (`stellereum/Cargo.toml:7`), not a git branch. But: no repo-root lock (no workspace manifest) and `cargo audit`/Dependabot wiring not evidenced. | fix-wave (CI check) |
| M-06 | STILL-OPEN | `rg compact` in `network.rs`/`consensus_net.rs`/`sync*` → zero transport hits (only QC-shape checks in `consensus.rs:3245,3415`); `stellereum/docs/program/COMPACT_PROPAGATION.md` + `PQ_TRANSPORT_PLAN.md` remain design docs; no measured-PQ end-to-end cited. | fix-wave |
| L-01 | STILL-OPEN | Plain `bincode::deserialize` on untrusted bytes persists: `network.rs:1782` (cross-shard), `rpc.rs:6497,3033,3313,5924`, `network.rs:344,589,1688,1891,2138`, `consensus_net.rs:2226,2260,3441`. Only `consensus_net.rs:449-450` uses `with_limit`. No central helper, no fuzz target cited. (Needs PoC — hypothesis, as in audit.) | fix-wave |
| L-02 | STILL-OPEN | FFI decls still unit-return, unchecked: `post_quantum.rs:1125-1145` (`PQCLEAN_FALCON512_CLEAN_keygen/sign_dyn` with no `-> i32`). Adjacent hygiene (`falcon_i8` → `Option`, W6.5 zeroization) does not check C return codes. | fix-wave |
| L-03 | STILL-OPEN | `Cell::new` still `assert!`-aborts (`cell.rs:26-35`). No `try_new`/`Result`. | fix-wave |
| L-04 | STILL-OPEN | `fetch_update` still used (`storage.rs:2982`). Clippy-clean claim unverified (no `cargo clippy` run in this session; 1-warning baseline from audit unrefuted). | fix-wave |
| L-05 | PARTIALLY-FIXED | `stellereum/docs/RPC.md` now accurate (open-submission-by-design + gated-method list). BUT `stellereum/docs/audits/KNOWN_ISSUES.md:301-312` (KI-19) still claims gated methods "fail closed … when auth_token is not configured" — false for gov/deploy/call arms (see H-01 evidence). | fix-wave (KI-19 text) |
| L-06 | STILL-OPEN | `derive_key` still returns `Ok(*key)` — copies out of `Zeroizing` (`node_keys.rs:100-111`), leaving the stack copy. | fix-wave |
| L-07 | STILL-OPEN | `from_boc_bytes` (`cell.rs:176-220` read) accepts arbitrary `refs_len`/`data_len` (only `offset+len ≤ blob` checked); no `refs_len ≤ 4` / `data_len ≤ 128` enforcement vs `Cell::new` invariants. | fix-wave |

## Counts

- ALREADY-FIXED: **1** (H-02)
- PARTIALLY-FIXED: **4** (H-01, M-02, M-05, L-05)
- STILL-OPEN: **14** (C-01, C-02, H-03, H-04, M-01, M-03, M-04, M-06, L-01, L-02, L-03, L-04, L-06, L-07)
- STALE-CLAIM: **0**

## Full OPEN list (STILL-OPEN IDs)

C-01, C-02, H-03, H-04, M-01, M-03, M-04, M-06, L-01, L-02, L-03, L-04, L-06, L-07.

## Notes (no new claims beyond evidence above)

- WORKING-TREE DRIFT (not triaged): after this triage's reads, the working tree gained
  **uncommitted** changes (`git diff --stat`: `rpc.rs +351/-75`, `runtime.rs +75`, `main.rs +18/-7`)
  that move the cited rows — e.g. `sweep_gov_finalize` (`runtime.rs:948`, wired at `:6422,6631,6935,6989,8358`)
  and `g.execute_at_height` (`rpc.rs:5999`). All verdicts above are against committed HEAD
  `4e3fcdd35` (re-verified via `git show HEAD:…`: `rpc.rs:5734/5776/5818`, `:6611/:6814`, `:6879`;
  `runtime.rs:2597` with no sweep). Re-triage C-02/H-01 after that work commits.
- Fix-wave = P0: C-01, C-02, H-01 (fail-closed decision), H-03, H-04; P1: M-01, M-02, M-03; P2: M-04 (DoS), M-05 (CI), M-06, L-01…L-07.
- "Known ALREADY-FIXED candidates" from the prompt: gov timelock (`GOV_TIMELOCK_HEIGHTS = 7_200`, `governance.rs:60`, landed in `24de1f85b`) mitigates KI-23 only — C-01/C-02 roots untouched. F10 allowlist (`runtime.rs:5862,9821`) and ML-DSA refusal (`wallet_signing.rs:278,397`) are §7/KNOWN_ISSUES context, not among the 19 rows. `Cargo.lock` per-crate present (see M-05). `pentest_net_api` batch test named in prompt was not found by that name in `stellereum/src|tests` (`rg batch_served|pentest_net_api` → no hits); batch-mirror contract comment lives in `post_quantum.rs:71-77`, batch tests green this session (`p5_contract_arms…`, `p5_call_contract_from_must_equal_signer` passed).
- No code, existing docs, or history were modified for this triage (read-only + this file). No `todo!`/dummy verdicts: every row cites a read or command output from this session.
